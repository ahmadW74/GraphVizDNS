import React, { useCallback, useEffect, useState, useRef } from "react";
import Graphviz from "graphviz-react";

/**
 * Renders a DNSSEC chain as a Graphviz diagram.
 *
 * @param {object} props
 * @param {string} props.domain - Domain to visualize
 * @param {number} [props.refreshTrigger] - Incrementing value to trigger reload
 */
const SampleGraph = ({ domain, refreshTrigger, theme }) => {
  const [dot, setDot] = useState("digraph DNSSEC {}");
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const containerRef = useRef(null);

  // Spacing configuration
  const horizontalSpacing = 1.5; // distance between nodes horizontally
  const verticalSpacing = 1.5; // distance between ranks vertically
  const rootOffset = 0.5; // extra left margin for the graph

  /**
   * Build a Graphviz dot string from API data.
   * The graph places each DNS level in a cluster box and connects
   * parent ZSKs to DS records and then to the child's KSK.
   * Unsigned levels are rendered in gray with red connecting arrows.
   */
  const buildDot = useCallback((data) => {
    if (!data || !Array.isArray(data.levels)) return "digraph DNSSEC {}";

    const statusColor = (status) => {
      if (status === "signed") return "palegreen";
      if (status === "partial") return "khaki";
      return "lightgray"; // unsigned
    };

    let dotStr =
      "digraph DNSSEC {\n" +
      "  rankdir=LR;\n" +
      `  nodesep=${horizontalSpacing};\n` +
      `  ranksep=${verticalSpacing};\n` +
      `  margin=${rootOffset};\n` +
      "  node [shape=box style=filled fontname=Helvetica fontsize=20 width=3 height=1.5];\n" +
      "  edge [penwidth=2];\n";

    // Create clusters for each level
    data.levels.forEach((level, idx) => {
      const fill = statusColor(level.dnssec_status?.status);
      const ksk = level.records?.dnskey_records?.find((k) => k.is_ksk);
      const zsk = level.records?.dnskey_records?.find((k) => k.is_zsk);
      const kskLabel = ksk
        ? `Key Signing Key\\n${ksk.algorithm_name}\\ntag ${ksk.key_tag}`
        : "Key Signing Key";
      const zskLabel = zsk
        ? `Zone Signing Key\\n${zsk.algorithm_name}\\ntag ${zsk.key_tag}`
        : "Zone Signing Key";

      dotStr += `  subgraph cluster_${idx} {\n    label="${level.display_name}";\n    style=rounded;\n`;

      if (idx === 0) {
      dotStr += `    anchor_${idx} [label="Trust Anchor" fillcolor="${fill}" tooltip="Root trust anchor"];\n`;
      }

      const kskTip = ksk ? `Key Signing Key\nAlgorithm: ${ksk.algorithm_name}\nTag: ${ksk.key_tag}` : "Key Signing Key";
      const zskTip = zsk ? `Zone Signing Key\nAlgorithm: ${zsk.algorithm_name}\nTag: ${zsk.key_tag}` : "Zone Signing Key";

      dotStr += `    ksk_${idx} [label="${kskLabel}" fillcolor="${fill}" tooltip="${kskTip}"];\n`;
      dotStr += `    zsk_${idx} [label="${zskLabel}" fillcolor="${fill}" tooltip="${zskTip}"];\n`;

      if (idx === 0) {
        dotStr += `    anchor_${idx} -> ksk_${idx};\n`;
      }

      dotStr += `    ksk_${idx} -> zsk_${idx};\n`;

      if (idx < data.levels.length - 1) {
        const child = data.levels[idx + 1];
        const dsRec =
          level.records?.ds_records?.[0] || child.records?.ds_records?.[0];
        const dsColor = dsRec ? "white" : "lightgray";
        const dsLabel = dsRec
          ? `Delegation Signer\\n${dsRec.algorithm_name}\\ntag ${dsRec.key_tag}`
          : "Delegation Signer";
        const dsId = `ds_${idx}_${idx + 1}`;
        const dsTip = dsRec ? `Delegation Signer\nAlgorithm: ${dsRec.algorithm_name}\nTag: ${dsRec.key_tag}` : "No DS record";
        dotStr += `    ${dsId} [label="${dsLabel}" shape=ellipse style=filled fillcolor="${dsColor}" tooltip="${dsTip}"];\n`;
      }

      dotStr += "  }\n";
    });

    // Connect levels using DS records
    for (let i = 0; i < data.levels.length - 1; i++) {
      const parent = data.levels[i];
      const child = data.levels[i + 1];

      const dsRec =
        parent.records?.ds_records?.[0] || child.records?.ds_records?.[0];
      const dsId = `ds_${i}_${i + 1}`;

      const arrow1 = dsRec ? "black" : "red";
      const childSigned = child.dnssec_status?.status === "signed";
      const arrow2 = dsRec && childSigned ? "black" : "red";

      dotStr += `  zsk_${i} -> ${dsId} [color=${arrow1}];\n`;
      dotStr += `  ${dsId} -> ksk_${i + 1} [color=${arrow2}];\n`;
    }

    dotStr += "}";
    return dotStr;
  }, []);

  const fetchData = useCallback(async () => {
    if (!domain) {
      setDot("digraph DNSSEC {}");
      setSummary(null);
      return;
    }

    try {
      setLoading(true);
      const res = await fetch(
        `http://127.0.0.1:8000/chain/${encodeURIComponent(domain)}`
      );
      const json = await res.json();
      setDot(buildDot(json));
      setSummary(json.chain_summary || null);
    } catch (err) {
      console.error("Failed to fetch DNSSEC chain", err);
      setDot("digraph DNSSEC {}");
      setSummary(null);
    } finally {
      setLoading(false);
    }
  }, [domain, buildDot]);

  useEffect(() => {
    fetchData();
  }, [fetchData, refreshTrigger]);


  if (!domain) {
    return (
      <div className="text-center text-gray-500">Enter a domain to visualize</div>
    );
  }

  if (loading) {
    return <div className="text-center">Loading...</div>;
  }

  return (
    <div className="w-full overflow-auto flex flex-col items-start relative">
      {summary && (
        <div
          className="absolute top-0 left-0 bg-card/80 p-2 rounded text-sm"
        >
          <p
            className={`font-semibold ${
              summary.security_status?.overall_status === "secure"
                ? "text-green-600"
                : summary.security_status?.overall_status === "broken"
                ? "text-red-600"
                : "text-yellow-600"
            }`}
          >
            Levels: {summary.total_levels} • Signed: {summary.signed_levels}
            • Breaks: {summary.chain_breaks?.length || 0}
          </p>
        </div>
      )}
      <div ref={containerRef} className="mt-8">
        <Graphviz dot={dot} />
      </div>
    </div>
  );
};

export default SampleGraph;
