import React, { useState, useRef, useEffect } from "react";
import {
  AlertCircle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Key,
  Globe,
  Database,
  RefreshCw,
  Search,
} from "lucide-react";

const DNSSECChainVisualizer = () => {
  const [data, setData] = useState(null);
  const [domain, setDomain] = useState("chatgpt.com");
  const [loading, setLoading] = useState(false);
  const [tooltip, setTooltip] = useState({
    show: false,
    content: "",
    x: 0,
    y: 0,
  });
  const containerRef = useRef(null);

  // Sample data for demonstration
  const sampleData = {
    metadata: {
      target_domain: "chatgpt.com",
      analysis_timestamp: "2025-06-02T15:55:19.222109",
      chain_length: 3,
      signed_levels: 3,
      chain_status: "broken",
      chain_message: "Chain break detected at 1 level(s)",
    },
    chain_summary: {
      total_levels: 3,
      signed_levels: 3,
      unsigned_levels: 0,
      chain_complete: false,
      chain_breaks: [
        {
          level: 1,
          domain: "com",
          reason: "Missing DS record in parent zone",
        },
      ],
    },
    levels: [
      {
        id: "level_0",
        index: 0,
        domain: ".",
        display_name: "ROOT",
        domain_type: "root",
        dnssec_status: {
          status: "signed",
          message: "Root zone is signed (trust anchor)",
          type: "success",
        },
        key_hierarchy: {
          ksk_count: 2,
          zsk_count: 1,
          total_keys: 3,
          ksk_keys: [
            {
              key_tag: 20326,
              algorithm_name: "RSASHA256",
              role: "KSK",
            },
            {
              key_tag: 38696,
              algorithm_name: "RSASHA256",
              role: "KSK",
            },
          ],
          zsk_keys: [
            {
              key_tag: 53148,
              algorithm_name: "RSASHA256",
              role: "ZSK",
            },
          ],
        },
        records: {
          ds_records: [],
          dnskey_records: 3,
        },
        chain_break_info: {
          has_chain_break: false,
        },
      },
      {
        id: "level_1",
        index: 1,
        domain: "com",
        display_name: "com",
        domain_type: "tld",
        dnssec_status: {
          status: "signed",
          message: "Fully signed with DNSSEC",
          type: "success",
        },
        key_hierarchy: {
          ksk_count: 1,
          zsk_count: 1,
          total_keys: 2,
          ksk_keys: [
            {
              key_tag: 19718,
              algorithm_name: "ECDSAP256SHA256",
              role: "KSK",
            },
          ],
          zsk_keys: [
            {
              key_tag: 40097,
              algorithm_name: "ECDSAP256SHA256",
              role: "ZSK",
            },
          ],
        },
        records: {
          ds_records: [
            {
              key_tag: 19718,
              algorithm_name: "ECDSAP256SHA256",
              digest_type_name: "SHA-256",
            },
          ],
          dnskey_records: 2,
        },
        chain_break_info: {
          has_chain_break: true,
          break_reason: "Missing DS record in parent zone",
        },
      },
      {
        id: "level_2",
        index: 2,
        domain: "chatgpt.com",
        display_name: "chatgpt.com",
        domain_type: "target",
        dnssec_status: {
          status: "partial",
          message: "Has DNSKEY but no DS record (unsigned delegation)",
          type: "warning",
        },
        key_hierarchy: {
          ksk_count: 1,
          zsk_count: 1,
          total_keys: 2,
          ksk_keys: [
            {
              key_tag: 2371,
              algorithm_name: "ECDSAP256SHA256",
              role: "KSK",
            },
          ],
          zsk_keys: [
            {
              key_tag: 34505,
              algorithm_name: "ECDSAP256SHA256",
              role: "ZSK",
            },
          ],
        },
        records: {
          ds_records: [],
          dnskey_records: 2,
        },
        chain_break_info: {
          has_chain_break: false,
        },
      },
    ],
  };

  useEffect(() => {
    setData(sampleData);
  }, []);

  const handleAnalyze = () => {
    setLoading(true);
    // Simulate API call
    setTimeout(() => {
      setData(sampleData);
      setLoading(false);
    }, 1000);
  };

  const handleRefresh = () => {
    setLoading(true);
    // Simulate refresh
    setTimeout(() => {
      setData({ ...sampleData });
      setLoading(false);
    }, 800);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "signed":
        return <ShieldCheck className="w-4 h-4 text-green-500" />;
      case "partial":
        return <ShieldAlert className="w-4 h-4 text-yellow-500" />;
      default:
        return <AlertCircle className="w-4 h-4 text-red-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "signed":
        return "bg-green-50 border-green-200";
      case "partial":
        return "bg-yellow-50 border-yellow-200";
      default:
        return "bg-red-50 border-red-200";
    }
  };

  const showTooltip = (e, content) => {
    const rect = containerRef.current.getBoundingClientRect();
    setTooltip({
      show: true,
      content,
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const hideTooltip = () => {
    setTooltip({ show: false, content: "", x: 0, y: 0 });
  };

  if (!data) return <div className="p-8">Loading...</div>;

  return (
    <div className="w-full h-screen bg-gray-50 p-6" ref={containerRef}>
      {/* Header */}
      <div className="mb-6 bg-white rounded-lg shadow-sm p-4">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-2xl font-bold text-gray-800">
            DNSSEC Chain Analyzer
          </h1>
          <div className="flex items-center gap-2">
            <div
              className={`px-3 py-1 rounded-full text-sm font-medium ${
                data.metadata.chain_status === "broken"
                  ? "bg-red-100 text-red-800"
                  : "bg-green-100 text-green-800"
              }`}
            >
              {data.metadata.chain_status.toUpperCase()}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex-1 flex items-center gap-2">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Enter domain name"
              className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              Analyze
            </button>
            <button
              onClick={handleRefresh}
              disabled={loading}
              className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 disabled:opacity-50 flex items-center gap-2"
            >
              <RefreshCw
                className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Chain Summary */}
      <div className="mb-6 bg-white rounded-lg shadow-sm p-4">
        <h2 className="text-lg font-semibold mb-3">Chain Summary</h2>
        <div className="grid grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">
              {data.chain_summary.total_levels}
            </div>
            <div className="text-sm text-gray-600">Total Levels</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">
              {data.chain_summary.signed_levels}
            </div>
            <div className="text-sm text-gray-600">Signed Levels</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">
              {data.chain_summary.chain_breaks?.length || 0}
            </div>
            <div className="text-sm text-gray-600">Chain Breaks</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-600">
              {data.chain_summary.unsigned_levels}
            </div>
            <div className="text-sm text-gray-600">Unsigned Levels</div>
          </div>
        </div>
      </div>

      {/* DNSSEC Chain Visualization */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h2 className="text-lg font-semibold mb-4">
          DNSSEC Chain Visualization
        </h2>

        <div className="relative">
          {data.levels.map((level, index) => (
            <div key={level.id} className="mb-8">
              {/* Domain Header */}
              <div
                className={`p-4 rounded-lg border-2 ${getStatusColor(
                  level.dnssec_status.status
                )} mb-4`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Globe className="w-6 h-6 text-blue-600" />
                    <div>
                      <h3 className="text-lg font-semibold">
                        {level.display_name}
                      </h3>
                      <p className="text-sm text-gray-600">
                        {level.domain_type.toUpperCase()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(level.dnssec_status.status)}
                    <span className="text-sm font-medium">
                      {level.dnssec_status.message}
                    </span>
                  </div>
                </div>
              </div>

              {/* Key Hierarchy */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 ml-8">
                {/* KSK Keys */}
                {level.key_hierarchy.ksk_keys?.map((key, keyIndex) => (
                  <div
                    key={`ksk-${keyIndex}`}
                    className="p-3 bg-blue-50 border border-blue-200 rounded-lg cursor-pointer hover:bg-blue-100"
                    onMouseEnter={(e) =>
                      showTooltip(
                        e,
                        `KSK Key Tag: ${key.key_tag}\nAlgorithm: ${key.algorithm_name}\nRole: ${key.role}`
                      )
                    }
                    onMouseLeave={hideTooltip}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Key className="w-4 h-4 text-blue-600" />
                      <span className="font-medium text-blue-800">KSK</span>
                    </div>
                    <div className="text-sm">
                      <div>Tag: {key.key_tag}</div>
                      <div className="text-gray-600">{key.algorithm_name}</div>
                    </div>
                  </div>
                ))}

                {/* ZSK Keys */}
                {level.key_hierarchy.zsk_keys?.map((key, keyIndex) => (
                  <div
                    key={`zsk-${keyIndex}`}
                    className="p-3 bg-green-50 border border-green-200 rounded-lg cursor-pointer hover:bg-green-100"
                    onMouseEnter={(e) =>
                      showTooltip(
                        e,
                        `ZSK Key Tag: ${key.key_tag}\nAlgorithm: ${key.algorithm_name}\nRole: ${key.role}`
                      )
                    }
                    onMouseLeave={hideTooltip}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Key className="w-4 h-4 text-green-600" />
                      <span className="font-medium text-green-800">ZSK</span>
                    </div>
                    <div className="text-sm">
                      <div>Tag: {key.key_tag}</div>
                      <div className="text-gray-600">{key.algorithm_name}</div>
                    </div>
                  </div>
                ))}

                {/* DS Records */}
                {level.records.ds_records?.length > 0 &&
                  level.records.ds_records.map((ds, dsIndex) => (
                    <div
                      key={`ds-${dsIndex}`}
                      className="p-3 bg-purple-50 border border-purple-200 rounded-lg cursor-pointer hover:bg-purple-100"
                      onMouseEnter={(e) =>
                        showTooltip(
                          e,
                          `DS Record\nKey Tag: ${ds.key_tag}\nAlgorithm: ${ds.algorithm_name}\nDigest: ${ds.digest_type_name}`
                        )
                      }
                      onMouseLeave={hideTooltip}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <Database className="w-4 h-4 text-purple-600" />
                        <span className="font-medium text-purple-800">DS</span>
                      </div>
                      <div className="text-sm">
                        <div>Tag: {ds.key_tag}</div>
                        <div className="text-gray-600">
                          {ds.digest_type_name}
                        </div>
                      </div>
                    </div>
                  ))}
              </div>

              {/* Chain Break Warning */}
              {level.chain_break_info?.has_chain_break && (
                <div className="mt-4 ml-8 p-3 bg-red-50 border-l-4 border-red-400 rounded">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="w-5 h-5 text-red-500" />
                    <span className="text-red-800 font-medium">
                      Chain Break Detected
                    </span>
                  </div>
                  <p className="text-red-700 text-sm mt-1">
                    {level.chain_break_info.break_reason}
                  </p>
                </div>
              )}

              {/* Connection Arrow */}
              {index < data.levels.length - 1 && (
                <div className="flex justify-center my-4">
                  <div className="w-px h-8 bg-gray-300 relative">
                    <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-2 h-2 bg-gray-400 rotate-45"></div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Tooltip */}
      {tooltip.show && (
        <div
          className="absolute z-50 bg-gray-800 text-white text-sm p-2 rounded shadow-lg pointer-events-none whitespace-pre-line"
          style={{
            left: tooltip.x + 10,
            top: tooltip.y - 10,
            maxWidth: "250px",
          }}
        >
          {tooltip.content}
        </div>
      )}
    </div>
  );
};

export default DNSSECChainVisualizer;
