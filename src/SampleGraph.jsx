import React, { useCallback, useEffect, useState } from "react";
import Graphviz from "graphviz-react";
import ErrorBoundary from "@/components/ErrorBoundary.jsx";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RotateCcw } from "lucide-react";
import { API_BASE } from "@/lib/api";

/**
 * Renders a DNSSEC chain as a Graphviz diagram.
 *
 * @param {object} props
 * @param {string} props.domain - Domain to visualize
 * @param {number} [props.refreshTrigger] - Incrementing value to trigger reload
 * @param {Function} [props.onRefresh] - Callback when the reload button is clicked
 */
const SampleGraph = ({ domain, refreshTrigger, onRefresh }) => {
  const [dot, setDot] = useState("digraph DNSSEC {}");
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const GRAPH_SCALE = 2;
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
      unsigned: { border: "#9E9E9E", apex: "#9E9E9E", apexFill: "#F5F5F5" },
    };

    let dotStr =
      "digraph DNSSEC_Chain {\n" +
      "  rankdir=LR;\n" +
      '  fontname="Helvetica";\n' +
      '  node [fontname="Helvetica", style=filled];\n';

    // Render each zone cluster
    data.levels.forEach((level, idx) => {
      const type =
        level.domain_type ||
        (idx === 0
          ? "root"
          : idx === data.levels.length - 1
          ? "target"
          : "tld");
      let colors = palette[type] || palette.target;
      if (level.dnssec_status?.status !== "signed") {
        colors = palette.unsigned;
      }
      if (level.chain_break_info?.has_chain_break) {
        colors = { border: "#D32F2F", apex: "#D32F2F", apexFill: "#FFCDD2" };
      }
      const ksk =
        level.records?.dnskey_records?.find((k) => k.is_ksk) ||
        level.key_hierarchy?.ksk_keys?.[0] ||
        (Array.isArray(level.records?.dnskey_records)
          ? level.records.dnskey_records.find((k) => k.role === "KSK")
          : null);
      const zsk =
        level.records?.dnskey_records?.find((k) => k.is_zsk) ||
        level.key_hierarchy?.zsk_keys?.[0] ||
        (Array.isArray(level.records?.dnskey_records)
          ? level.records.dnskey_records.find((k) => k.role === "ZSK")
          : null);
      const kskInfo = ksk
        ? `Key ID ${ksk.key_tag} | Algo ${ksk.algorithm_name || ksk.algorithm}`
        : "";
      const zskInfo = zsk
        ? `Key ID ${zsk.key_tag} | Algo ${zsk.algorithm_name || zsk.algorithm}`
        : "";

      dotStr += `  subgraph cluster_${idx} {\n`;
      const zoneLabel =
        idx === 0
          ? `Root Zone (${level.display_name})`
          : idx === data.levels.length - 1
          ? level.display_name
          : `${level.display_name} Zone`;
      dotStr += `    label="${zoneLabel}";\n`;
      dotStr += `    style="rounded,dashed";\n`;
      dotStr += `    color="${colors.border}";\n\n`;

      dotStr += `    apex_${idx} [label="${level.display_name}" shape=rect fillcolor="${colors.apexFill}" color="${colors.apex}"];\n`;

      dotStr += `    keyset_${idx} [shape=record fillcolor="#E3F2FD" color="#2196F3" label="{ {<ksk> KSK | ${kskInfo} } | {<zsk> ZSK | ${zskInfo} } }"];\n`;

      const hasDNSKEY =
        Array.isArray(level.records?.dnskey_records) &&
        level.records.dnskey_records.length > 0;

      if (idx !== 0) {
        if (hasDNSKEY) {
          dotStr += `    dnskey_rrset_${idx} [label="DNSKEY Records" shape=ellipse fillcolor="#BBDEFB" color="#1976D2"];\n`;
          dotStr += `    {rank=same; dnskey_rrset_${idx}; keyset_${idx};}\n`;
        } else {
          dotStr += `    dnskey_rrset_${idx} [label="No DNSKEY" shape=ellipse style=dashed color="#D32F2F"];\n`;
        }
      }

      dotStr += `    ds_rrset_${idx} [label="DS Records" shape=ellipse fillcolor="#E1BEE7" color="#8E24AA"];\n`;

      if (idx < data.levels.length - 1) {
        const child = data.levels[idx + 1];
        const ds = child.records?.ds_records?.[0];
        const childBreak = child.chain_break_info?.has_chain_break;
        const breakReason = child.chain_break_info?.break_reason || "";

        if (ds) {
          const digest = ds.digest ? ds.digest.slice(0, 8) + "…" : "";
          const fill =
            childBreak && breakReason.toLowerCase().includes("dnskey")
              ? "#FFCDD2"
              : "#EDE7F6";
          const col =
            childBreak && breakReason.toLowerCase().includes("dnskey")
              ? "#D32F2F"
              : "#673AB7";
          dotStr += `    ds_for_${idx}_${idx + 1} [label=< <b>DS for ${
            child.display_name
          }</b><br/>Key ID ${ds.key_tag}<br/>Digest Type ${
            ds.digest_type
          }<br/>Digest: ${digest} >, shape=box style="rounded,filled" fillcolor="${fill}" color="${col}"];\n`;
        } else {
          dotStr += `    ds_for_${idx}_${idx + 1} [label=< <b>No DS for ${
            child.display_name
          }</b> >, shape=box style="rounded,filled" fillcolor="#FFEBEE" color="#C62828"];\n`;
        }
      }

      if (idx === 0) {
        if (hasDNSKEY) {
          dotStr += `    apex_${idx} -> keyset_${idx}:ksk [label="has DNSKEYs" color="#1976D2"];\n`;
        }
      } else {
        if (hasDNSKEY) {
          dotStr += `    apex_${idx} -> dnskey_rrset_${idx} [label="has" color="#1976D2"];\n`;
          dotStr += `    dnskey_rrset_${idx} -> keyset_${idx}:ksk [color="#1976D2"];\n`;
          dotStr += `    dnskey_rrset_${idx} -> keyset_${idx}:zsk [color="#1976D2"];\n`;
        } else {
          dotStr += `    apex_${idx} -> keyset_${idx} [style=dashed color="#D32F2F"];\n`;
        }
      }
      dotStr += `    apex_${idx} -> ds_rrset_${idx} [label="has" color="#8E24AA"];\n`;
      if (idx < data.levels.length - 1) {
        const child = data.levels[idx + 1];
        const ds = child.records?.ds_records?.[0];
        const childBreak = child.chain_break_info?.has_chain_break;
        const breakReason = child.chain_break_info?.break_reason || "";

        if (ds) {
          dotStr += `    ds_rrset_${idx} -> ds_for_${idx}_${
            idx + 1
          } [color="#8E24AA"];\n`;
          dotStr += `    keyset_${idx}:zsk -> ds_for_${idx}_${
            idx + 1
          } [label="signs" color="#4CAF50"];\n`;
          const edgeStyle =
            childBreak && breakReason.toLowerCase().includes("dnskey")
              ? 'color="#D32F2F" style=dashed'
              : 'color="#4CAF50" penwidth=2';
          dotStr += `    ds_for_${idx}_${idx + 1} -> keyset_${
            idx + 1
          }:ksk [label="validates" ${edgeStyle}];\n`;
        } else {
          dotStr += `    ds_rrset_${idx} -> ds_for_${idx}_${
            idx + 1
          } [style=dashed color="#C62828"];\n`;
        }
      }
      dotStr += `    keyset_${idx}:ksk -> keyset_${idx}:zsk [style=dotted arrowhead=none color="#424242"];\n`;

      dotStr += "  }\n";
    });

    // Delegation edges between zones
    for (let i = 0; i < data.levels.length - 1; i++) {
      dotStr += `  apex_${i} -> apex_${
        i + 1
      } [label="delegates to" color="#FF9800" style=dashed];\n`;
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
      <div className="text-center text-gray-500">
        Enter a domain to visualize
      </div>
    );
  }

  if (loading) {
    return <div className="text-center">Loading...</div>;
  }

  return (
    <div className="relative">
      <Card className="w-full bg-card border-border">
        <CardContent className="relative px-6 py-6 lg:px-8 lg:py-8 flex justify-center overflow-auto">
          <div className="w-full overflow-hidden flex flex-col gap-4">
            {summary && (
              <div className="text-left">
                <h2 className="font-semibold text-lg text-foreground">
                  {domain}
                </h2>
                <p className="text-sm text-muted-foreground">
                  Levels: {summary.total_levels} • Signed:{" "}
                  {summary.signed_levels} • Breaks:{" "}
                  {summary.chain_breaks?.length || 0}
                </p>
              </div>
            )}
            <div
              className=" overflow-hidden flex justify-center"
              style={{
                transform: `scale(2)`,
              }}
            >
              <ErrorBoundary>
                <Graphviz dot={dot} options={{ engine: "dot" }} />
              </ErrorBoundary>
            </div>
          </div>
        </CardContent>
      </Card>
      <Button
        size="icon"
        variant="secondary"
        onClick={onRefresh}
        disabled={!domain}
        className="absolute -right-16 top-4 h-12 w-12"
      >
        <RotateCcw className="h-6 w-6" />
      </Button>
    </div>
  );
};

export default SampleGraph;
