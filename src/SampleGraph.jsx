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
  const [tooltip, setTooltip] = useState({ show: false, x: 0, y: 0, content: "" });
  const containerRef = useRef(null);

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
      "  rankdir=TB;\n" +
      "  node [shape=box style=filled fontname=Helvetica fontsize=16 width=2 height=1];\n" +
      "  edge [penwidth=2];\n";

    // Create clusters for each level
    data.levels.forEach((level, idx) => {
      const fill = statusColor(level.dnssec_status?.status);
      const ksk = level.records?.dnskey_records?.find((k) => k.is_ksk);
      const zsk = level.records?.dnskey_records?.find((k) => k.is_zsk);
      const kskLabel = ksk
        ? `KSK\\n${ksk.algorithm_name}\\ntag ${ksk.key_tag}`
        : "KSK";
      const zskLabel = zsk
        ? `ZSK\\n${zsk.algorithm_name}\\ntag ${zsk.key_tag}`
        : "ZSK";

      dotStr += `  subgraph cluster_${idx} {\n    label="${level.display_name}";\n    style=rounded;\n`;

      if (idx === 0) {
      dotStr += `    anchor_${idx} [label="Anchor KSK" fillcolor="${fill}" tooltip="Root trust anchor"];\n`;
      }

      const kskTip = ksk ? `KSK\nAlgorithm: ${ksk.algorithm_name}\nTag: ${ksk.key_tag}` : "KSK";
      const zskTip = zsk ? `ZSK\nAlgorithm: ${zsk.algorithm_name}\nTag: ${zsk.key_tag}` : "ZSK";

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
          ? `DS\\n${dsRec.algorithm_name}\\ntag ${dsRec.key_tag}`
          : "DS";
        const dsId = `ds_${idx}_${idx + 1}`;
        const dsTip = dsRec ? `DS\nAlgorithm: ${dsRec.algorithm_name}\nTag: ${dsRec.key_tag}` : "No DS record";
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

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const enter = (e) => {
      const node = e.currentTarget;
      // Fallback: if tooltip info hasn't been processed yet, grab it now
      if (!node.dataset.tooltip) {
        const t = node.querySelector('title');
        if (t) {
          node.dataset.tooltip = t.textContent || '';
          t.remove();
        } else if (node.getAttribute('title')) {
          node.dataset.tooltip = node.getAttribute('title');
          node.removeAttribute('title');
        }
      }
      const tip = node.dataset.tooltip;
      if (tip) {
        setTooltip({ show: true, x: e.clientX, y: e.clientY, content: tip });
      }
    };
    const move = (e) => {
      setTooltip((tt) => ({ ...tt, x: e.clientX, y: e.clientY }));
    };
    const leave = () => setTooltip((tt) => ({ ...tt, show: false }));

    const processNodes = () => {
      // Remove all <title> elements generated by Graphviz and store their text
      container.querySelectorAll('title').forEach((t) => {
        const parent = t.parentElement;
        if (parent && !parent.dataset.tooltip) {
          parent.dataset.tooltip = t.textContent || '';
        }
        t.remove();
      });

      // Also handle elements that use a title attribute as a fallback
      container.querySelectorAll('[title]').forEach((el) => {
        if (!el.dataset.tooltip) {
          el.dataset.tooltip = el.getAttribute('title') || '';
        }
        el.removeAttribute('title');
      });

      container.querySelectorAll('g').forEach((n) => {
        n.removeEventListener('mouseenter', enter);
        n.removeEventListener('mousemove', move);
        n.removeEventListener('mouseleave', leave);
        n.addEventListener('mouseenter', enter);
        n.addEventListener('mousemove', move);
        n.addEventListener('mouseleave', leave);
      });
    };

    processNodes();

    const observer = new MutationObserver(() => processNodes());
    observer.observe(container, { childList: true, subtree: true });

    return () => {
      observer.disconnect();
      container.querySelectorAll('g').forEach((n) => {
        n.removeEventListener('mouseenter', enter);
        n.removeEventListener('mousemove', move);
        n.removeEventListener('mouseleave', leave);
      });
    };
  }, [dot]);

  if (!domain) {
    return (
      <div className="text-center text-gray-500">Enter a domain to visualize</div>
    );
  }

  if (loading) {
    return <div className="text-center">Loading...</div>;
  }

  const tooltipStyle =
    theme === 'light'
      ? 'bg-white text-gray-800 border border-gray-300'
      : theme === 'high-contrast'
      ? 'bg-black text-yellow-300 border border-yellow-300'
      : 'bg-gray-800 text-white';

  return (
    <div className="w-full overflow-x-auto flex justify-center relative">
      <div ref={containerRef} className="mt-[-20px]">
        <Graphviz dot={dot} options={{ fit: true, width: 800, height: 600 }} />
      </div>
      {tooltip.show && (
        <div
          className={`absolute pointer-events-none px-2 py-1 rounded shadow z-50 ${tooltipStyle}`}
          style={{ left: tooltip.x + 10, top: tooltip.y + 10 }}
        >
          {tooltip.content.split('\n').map((line, i) => (
            <div key={i}>{line}</div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SampleGraph;
