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

  /**
   * Build a Graphviz dot string from API data.
   * The graph places each DNS level in a cluster box and connects
   * parent ZSKs to DS records and then to the child's KSK.
   * Unsigned levels are rendered in gray with red connecting arrows.
   */
  const buildDot = useCallback((data) => {
    if (!data || !Array.isArray(data.levels)) return "digraph{}";

    const palette = {
      root: { border: "#FB8C00", apex: "#FB8C00", apexFill: "#FFF3E0" },
      tld: { border: "#FF9800", apex: "#FF9800", apexFill: "#FFE0B2" },
      target: { border: "#4CAF50", apex: "#2E7D32", apexFill: "#C8E6C9" },
      subdomain: { border: "#4CAF50", apex: "#2E7D32", apexFill: "#C8E6C9" },
    };

    let dotStr =
      'digraph DNSSEC_Chain {\n' +
      '  rankdir=LR;\n' +
      '  fontname="Helvetica";\n' +
      '  node [fontname="Helvetica", style=filled];\n';

    // Render each zone cluster
    data.levels.forEach((level, idx) => {
      const type = level.domain_type ||
        (idx === 0 ? 'root' : idx === data.levels.length - 1 ? 'target' : 'tld');
      const colors = palette[type] || palette.target;
      const ksk = level.records?.dnskey_records?.find((k) => k.is_ksk);
      const zsk = level.records?.dnskey_records?.find((k) => k.is_zsk);
      const kskInfo = ksk
        ? `Key ID ${ksk.key_tag} | Algo ${ksk.algorithm}`
        : '';
      const zskInfo = zsk
        ? `Key ID ${zsk.key_tag} | Algo ${zsk.algorithm}`
        : '';

      dotStr += `  subgraph cluster_${idx} {\n`;
      const zoneLabel = idx === 0
        ? `Root Zone (${level.display_name})`
        : idx === data.levels.length - 1
          ? level.display_name
          : `${level.display_name} Zone`;
      dotStr += `    label="${zoneLabel}";\n`;
      dotStr += `    style="rounded,dashed";\n`;
      dotStr += `    color="${colors.border}";\n\n`;

      dotStr += `    apex_${idx} [label="${level.display_name}" shape=rect fillcolor="${colors.apexFill}" color="${colors.apex}"];\n`;

      dotStr += `    keyset_${idx} [shape=record fillcolor="#E3F2FD" color="#2196F3" label="{ {<ksk> KSK | ${kskInfo} } | {<zsk> ZSK | ${zskInfo} } }"];\n`;
      if (idx !== 0) {
        dotStr += `    dnskey_rrset_${idx} [label="DNSKEY Records" shape=ellipse fillcolor="#BBDEFB" color="#1976D2"];\n`;
      }

      dotStr += `    ds_rrset_${idx} [label="DS Records" shape=ellipse fillcolor="#E1BEE7" color="#8E24AA"];\n`;

      if (idx < data.levels.length - 1) {
        const child = data.levels[idx + 1];
        const ds = child.records?.ds_records?.[0];
        if (ds) {
          const digest = ds.digest ? ds.digest.slice(0, 8) + '…' : '';
          dotStr +=
            `    ds_for_${idx}_${idx + 1} [label=< <b>DS for ${child.display_name}</b><br/>Key ID ${ds.key_tag}<br/>Digest Type ${ds.digest_type}<br/>Digest: ${digest} >, shape=box style="rounded,filled" fillcolor="#EDE7F6" color="#673AB7"];\n`;
        }
      }

      if (idx === 0) {
        dotStr += `    apex_${idx} -> keyset_${idx}:ksk [label="has DNSKEYs" color="#1976D2"];\n`;
      } else {
        dotStr += `    apex_${idx} -> dnskey_rrset_${idx} [label="has" color="#1976D2"];\n`;
        dotStr += `    dnskey_rrset_${idx} -> keyset_${idx}:ksk [color="#1976D2"];\n`;
        dotStr += `    dnskey_rrset_${idx} -> keyset_${idx}:zsk [color="#1976D2"];\n`;
      }
      dotStr += `    apex_${idx} -> ds_rrset_${idx} [label="has" color="#8E24AA"];\n`;
      if (idx < data.levels.length - 1) {
        const child = data.levels[idx + 1];
        const ds = child.records?.ds_records?.[0];
        if (ds) {
          dotStr +=
            `    ds_rrset_${idx} -> ds_for_${idx}_${idx + 1} [color="#8E24AA"];\n`;
          dotStr +=
            `    ds_for_${idx}_${idx + 1} -> keyset_${idx + 1}:ksk [label="validates" color="#4CAF50" penwidth=2];\n`;
        }
      }
      dotStr +=
        `    keyset_${idx}:ksk -> keyset_${idx}:zsk [style=dotted arrowhead=none color="#424242"];\n`;

      dotStr += '  }\n';
    });

    // Delegation edges between zones
    for (let i = 0; i < data.levels.length - 1; i++) {
      dotStr += `  apex_${i} -> apex_${i + 1} [label="delegates to" color="#FF9800" style=dashed];\n`;
    }

    dotStr += '}';
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
    <div className="w-full overflow-auto flex flex-col gap-4">
      {summary && (
        <div className="text-left">
          <h2 className="font-semibold text-lg text-foreground">{domain}</h2>
          <p className="text-sm text-muted-foreground">
            Levels: {summary.total_levels} • Signed: {summary.signed_levels} •
            Breaks: {summary.chain_breaks?.length || 0}
          </p>
        </div>
      )}
      <div ref={containerRef} className="w-full overflow-auto flex justify-center">
        <Graphviz
          dot={dot}
          options={{ engine: "dot" }}
          style={{ width: "100%", minHeight: "600px" }}
        />
      </div>
    </div>
  );
};

export default SampleGraph;
