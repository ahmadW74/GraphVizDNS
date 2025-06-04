import React, { useCallback, useEffect, useState } from "react";
import Graphviz from "graphviz-react";

/**
 * Renders a DNSSEC chain as a Graphviz diagram.
 *
 * @param {object} props
 * @param {string} props.domain - Domain to visualize
 * @param {number} [props.refreshTrigger] - Incrementing value to trigger reload
 */
const SampleGraph = ({ domain, refreshTrigger }) => {
  const [dot, setDot] = useState("digraph DNSSEC {}");
  const [loading, setLoading] = useState(false);

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
      "digraph DNSSEC {\n  rankdir=TB;\n  node [shape=box style=filled fontname=Helvetica];\n";

    // Create clusters for each level
    data.levels.forEach((level, idx) => {
      const fill = statusColor(level.dnssec_status?.status);
      const ksk = level.records?.dnskey_records?.find((k) => k.is_ksk);
      const zsk = level.records?.dnskey_records?.find((k) => k.is_zsk);
      const kskTip = ksk
        ? `alg: ${ksk.algorithm_name}\\nsize: ${ksk.key_size}\\ntag: ${ksk.key_tag}`
        : "no KSK";
      const zskTip = zsk
        ? `alg: ${zsk.algorithm_name}\\nsize: ${zsk.key_size}\\ntag: ${zsk.key_tag}`
        : "no ZSK";

      dotStr += `  subgraph cluster_${idx} {\n    label="${level.display_name}";\n    style=rounded;\n    ksk_${idx} [label="KSK" fillcolor="${fill}" tooltip="${kskTip}"];\n    zsk_${idx} [label="ZSK" fillcolor="${fill}" tooltip="${zskTip}"];\n    ksk_${idx} -> zsk_${idx};\n  }\n`;
    });

    // Connect levels using DS records
    for (let i = 0; i < data.levels.length - 1; i++) {
      const parent = data.levels[i];
      const child = data.levels[i + 1];

      // DS may exist in the parent or in the child zone
      const dsRec = parent.records?.ds_records?.[0] || child.records?.ds_records?.[0];
      const dsId = `ds_${i}_${i + 1}`;
      const dsTip = dsRec
        ? `alg: ${dsRec.algorithm_name}\\ntag: ${dsRec.key_tag}`
        : "No DS record";
      const dsColor = dsRec ? "white" : "lightgray";

      dotStr += `  ${dsId} [label="DS" shape=ellipse style=filled fillcolor="${dsColor}" tooltip="${dsTip}"];\n`;

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
      return;
    }

    try {
      setLoading(true);
      const res = await fetch(
        `http://127.0.0.1:8000/chain/${encodeURIComponent(domain)}`
      );
      const json = await res.json();
      setDot(buildDot(json));
    } catch (err) {
      console.error("Failed to fetch DNSSEC chain", err);
      setDot("digraph DNSSEC {}");
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
    <div className="w-full overflow-x-auto">
      <Graphviz dot={dot} options={{ fit: true }} />
    </div>
  );
};

export default SampleGraph;
