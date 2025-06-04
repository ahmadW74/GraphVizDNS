import React, { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Key,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
} from "lucide-react";

// Sample data for fallback/demo purposes
const sampleData = {
  metadata: {
    target_domain: "example.com",
    analysis_timestamp: new Date().toISOString(),
  },
  chain_summary: {
    security_status: {
      overall_status: "secure",
      message: "DNSSEC chain is properly configured and secure",
    },
    total_levels: 3,
    signed_levels: 3,
    unsigned_levels: 0,
    chain_breaks: [],
  },
  levels: [
    {
      id: "root",
      display_name: ".",
      dnssec_status: {
        status: "signed",
        message: "Root zone is properly signed",
      },
      key_hierarchy: {
        ksk_count: 2,
        zsk_count: 1,
        ksk_keys: [
          {
            algorithm_name: "RSASHA256",
            key_tag: "12345",
          },
        ],
      },
      records: {
        ds_records: [],
        dnskey_records: [{ key_tag: "12345" }],
        ns_records: ["a.root-servers.net", "b.root-servers.net"],
        soa_record: { ttl: 86400 },
      },
      chain_break_info: null,
    },
    {
      id: "tld",
      display_name: "com.",
      dnssec_status: {
        status: "signed",
        message: "TLD is properly signed",
      },
      key_hierarchy: {
        ksk_count: 1,
        zsk_count: 1,
        ksk_keys: [
          {
            algorithm_name: "RSASHA256",
            key_tag: "54321",
          },
        ],
      },
      records: {
        ds_records: [{ key_tag: "54321" }],
        dnskey_records: [{ key_tag: "54321" }],
        ns_records: ["a.gtld-servers.net", "b.gtld-servers.net"],
        soa_record: { ttl: 172800 },
      },
      chain_break_info: null,
    },
    {
      id: "domain",
      display_name: "example.com.",
      dnssec_status: {
        status: "signed",
        message: "Domain is properly signed",
      },
      key_hierarchy: {
        ksk_count: 1,
        zsk_count: 1,
        ksk_keys: [
          {
            algorithm_name: "RSASHA256",
            key_tag: "67890",
          },
        ],
      },
      records: {
        ds_records: [{ key_tag: "67890" }],
        dnskey_records: [{ key_tag: "67890" }],
        ns_records: ["ns1.example.com", "ns2.example.com"],
        soa_record: { ttl: 3600 },
      },
      chain_break_info: null,
    },
  ],
};

function DNSSECVisualizer({ domain, onRefresh, refreshTrigger }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchDNSSECData = useCallback(async () => {
    if (!domain) {
      setData(null);
      setError(null);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Replace with your actual API endpoint
      const response = await fetch(
        `http://127.0.0.1:8000/chain/${encodeURIComponent(domain)}`
      );

      if (!response.ok) {
        throw new Error(
          `Failed to fetch DNSSEC data: ${response.status} ${response.statusText}`
        );
      }

      const result = await response.json();
      setData(result);
    } catch (err) {
      console.error("Error fetching DNSSEC data:", err);
      setError(err.message);
      // Fallback to sample data for demonstration
      setData({
        ...sampleData,
        metadata: {
          ...sampleData.metadata,
          target_domain: domain,
        },
      });
    } finally {
      setLoading(false);
    }
  }, [domain]);

  // Fetch data when domain changes
  useEffect(() => {
    fetchDNSSECData();
  }, [fetchDNSSECData]);

  // Handle refresh trigger from parent
  useEffect(() => {
    if (refreshTrigger && domain) {
      fetchDNSSECData();
    }
  }, [refreshTrigger, fetchDNSSECData, domain]);

  const getStatusIcon = (status, hasChainBreak = false) => {
    if (hasChainBreak) return <ShieldX className="w-5 h-5 text-red-500" />;

    switch (status) {
      case "signed":
        return <ShieldCheck className="w-5 h-5 text-green-500" />;
      case "partial":
        return <ShieldAlert className="w-5 h-5 text-yellow-500" />;
      case "unsigned":
        return <Shield className="w-5 h-5 text-gray-400" />;
      default:
        return <Shield className="w-5 h-5 text-gray-400" />;
    }
  };

  const getStatusColor = (status, hasChainBreak = false) => {
    if (hasChainBreak) return "border-red-500 bg-red-50";

    switch (status) {
      case "signed":
        return "border-green-500 bg-green-50";
      case "partial":
        return "border-yellow-500 bg-yellow-50";
      case "unsigned":
        return "border-gray-300 bg-gray-50";
      default:
        return "border-gray-300 bg-gray-50";
    }
  };

  const getStatusBadgeColor = (status, hasChainBreak = false) => {
    if (hasChainBreak) return "bg-red-100 text-red-800";

    switch (status) {
      case "signed":
        return "bg-green-100 text-green-800";
      case "partial":
        return "bg-yellow-100 text-yellow-800";
      case "unsigned":
        return "bg-gray-100 text-gray-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  // Check if this is a root-TLD relationship where DS records might not be present
  const shouldShowDSError = (level, index, levels) => {
    if (!level.chain_break_info?.has_chain_break) return false;

    // Don't show DS-related errors for root zone or if it's a root-TLD relationship
    if (index === 0) return false; // Root zone

    // Check if this is TLD level and the error is DS-related
    if (
      index === 1 &&
      level.chain_break_info?.break_reason?.toLowerCase().includes("ds")
    ) {
      return false; // Don't show DS errors for TLD as DS can be present in TLD
    }

    return true;
  };

  const DomainBox = ({ level, index, total, levels }) => {
    const hasChainBreak = level.chain_break_info?.has_chain_break || false;
    const showError = shouldShowDSError(level, index, levels);
    const displayChainBreak = hasChainBreak && showError;

    const statusColor = getStatusColor(
      level.dnssec_status?.status || "unsigned",
      displayChainBreak
    );
    const badgeColor = getStatusBadgeColor(
      level.dnssec_status?.status || "unsigned",
      displayChainBreak
    );

    return (
      <TooltipProvider>
        <div className="relative flex flex-col items-center">
          {/* Connection Arrow */}
          {index < total - 1 && (
            <div className="absolute top-full left-1/2 transform -translate-x-1/2 z-10">
              <div className="w-0.5 h-12 bg-gradient-to-b from-blue-400 to-blue-600"></div>
              <div className="absolute -bottom-1 left-1/2 transform -translate-x-1/2">
                <div className="w-0 h-0 border-l-[6px] border-r-[6px] border-t-[8px] border-l-transparent border-r-transparent border-t-blue-600"></div>
              </div>
            </div>
          )}

          <Tooltip>
            <TooltipTrigger asChild>
              <Card
                className={`w-80 cursor-pointer transition-all duration-200 hover:shadow-lg border-2 ${statusColor}`}
              >
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center justify-between text-lg">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(
                        level.dnssec_status?.status || "unsigned",
                        displayChainBreak
                      )}
                      <span className="font-mono">{level.display_name}</span>
                    </div>
                    <Badge className={`text-xs ${badgeColor}`}>
                      {displayChainBreak
                        ? "BROKEN"
                        : (
                            level.dnssec_status?.status || "unsigned"
                          ).toUpperCase()}
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Key Information */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1">
                      <Key className="w-4 h-4 text-blue-500" />
                      <span className="text-sm text-gray-600">Keys</span>
                    </div>
                    <div className="flex gap-2">
                      {(level.key_hierarchy?.ksk_count || 0) > 0 && (
                        <Badge
                          variant="outline"
                          className="text-xs bg-blue-50 text-blue-700"
                        >
                          KSK: {level.key_hierarchy.ksk_count}
                        </Badge>
                      )}
                      {(level.key_hierarchy?.zsk_count || 0) > 0 && (
                        <Badge
                          variant="outline"
                          className="text-xs bg-purple-50 text-purple-700"
                        >
                          ZSK: {level.key_hierarchy.zsk_count}
                        </Badge>
                      )}
                    </div>
                  </div>

                  {/* Records Count */}
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div className="text-center p-2 bg-white rounded border">
                      <div className="font-semibold text-green-600">
                        {level.records?.ds_records?.length || 0}
                      </div>
                      <div className="text-gray-500">DS</div>
                    </div>
                    <div className="text-center p-2 bg-white rounded border">
                      <div className="font-semibold text-blue-600">
                        {level.records?.dnskey_records?.length || 0}
                      </div>
                      <div className="text-gray-500">DNSKEY</div>
                    </div>
                    <div className="text-center p-2 bg-white rounded border">
                      <div className="font-semibold text-purple-600">
                        {level.records?.ns_records?.length || 0}
                      </div>
                      <div className="text-gray-500">NS</div>
                    </div>
                  </div>

                  {/* Status Message */}
                  <div className="flex items-start gap-2 p-2 bg-white rounded border">
                    {displayChainBreak ? (
                      <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                    ) : (level.dnssec_status?.status || "unsigned") ===
                      "signed" ? (
                      <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                    )}
                    <span className="text-xs text-gray-700">
                      {displayChainBreak
                        ? level.chain_break_info.break_reason
                        : level.dnssec_status?.message || "Status unknown"}
                    </span>
                  </div>
                </CardContent>
              </Card>
            </TooltipTrigger>
            <TooltipContent side="right" className="max-w-md">
              <div className="space-y-2">
                <div className="font-semibold text-sm">
                  {level.display_name} Details
                </div>

                {/* Algorithm Info */}
                {level.key_hierarchy?.ksk_keys?.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-gray-600">
                      Algorithm:
                    </div>
                    <div className="text-xs">
                      {level.key_hierarchy.ksk_keys[0].algorithm_name}
                    </div>
                  </div>
                )}

                {/* Key Tags */}
                {level.records?.dnskey_records?.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-gray-600">
                      Key Tags:
                    </div>
                    <div className="flex flex-wrap gap-1 text-white">
                      {level.records.dnskey_records.map((key, idx) => (
                        <Badge
                          key={idx}
                          variant="outline"
                          className="text-white-xs"
                        >
                          {key.key_tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Name Servers */}
                {level.records?.ns_records?.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-gray-600">
                      Name Servers:
                    </div>
                    <div className="text-xs max-h-20 overflow-y-auto">
                      {level.records.ns_records.slice(0, 3).map((ns, idx) => (
                        <div key={idx}>{ns}</div>
                      ))}
                      {level.records.ns_records.length > 3 && (
                        <div className="text-gray-500">
                          ... and {level.records.ns_records.length - 3} more
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* TTL Info */}
                {level.records?.soa_record && (
                  <div>
                    <div className="text-xs font-medium text-gray-600">
                      SOA TTL:
                    </div>
                    <div className="text-xs">
                      {level.records.soa_record.ttl}s
                    </div>
                  </div>
                )}
              </div>
            </TooltipContent>
          </Tooltip>
        </div>
      </TooltipProvider>
    );
  };

  const ChainSummary = ({ summary }) => {
    const overallStatus = summary.security_status?.overall_status || "unknown";
    const statusIcon =
      overallStatus === "broken" ? (
        <XCircle className="w-6 h-6 text-red-500" />
      ) : overallStatus === "secure" ? (
        <CheckCircle className="w-6 h-6 text-green-500" />
      ) : (
        <AlertTriangle className="w-6 h-6 text-yellow-500" />
      );

    const statusColor =
      overallStatus === "broken"
        ? "border-red-200 bg-red-50"
        : overallStatus === "secure"
        ? "border-green-200 bg-green-50"
        : "border-yellow-200 bg-yellow-50";

    return (
      <Card className={`mb-8 ${statusColor} border-2`}>
        <CardHeader>
          <CardTitle className="flex items-center gap-3">
            {statusIcon}
            <span className="text-black">DNSSEC Chain Analysis</span>
            <Badge
              className={
                overallStatus === "broken"
                  ? "bg-red-100 text-red-800"
                  : overallStatus === "secure"
                  ? "bg-green-100 text-green-800"
                  : "bg-yellow-100 text-yellow-800"
              }
            >
              {overallStatus.toUpperCase()}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {summary.total_levels || 0}
              </div>
              <div className="text-sm text-gray-600">Total Levels</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {summary.signed_levels || 0}
              </div>
              <div className="text-sm text-gray-600">Signed Levels</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-600">
                {summary.unsigned_levels || 0}
              </div>
              <div className="text-sm text-gray-600">Unsigned Levels</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">
                {summary.chain_breaks?.length || 0}
              </div>
              <div className="text-sm text-gray-600">Chain Breaks</div>
            </div>
          </div>

          {summary.chain_breaks?.length > 0 && (
            <div className="mt-4 p-3 bg-red-100 rounded-lg border border-red-200">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-red-600" />
                <span className="font-medium text-red-800">
                  Chain Breaks Detected
                </span>
              </div>
              {summary.chain_breaks.map((breakInfo, idx) => (
                <div key={idx} className="text-sm text-red-700">
                  <strong>{breakInfo.domain}:</strong> {breakInfo.reason}
                </div>
              ))}
            </div>
          )}

          <div className="mt-4 p-3 bg-white rounded-lg border">
            <div className="flex items-center gap-2">
              {overallStatus === "broken" ? (
                <XCircle className="w-4 h-4 text-red-500" />
              ) : overallStatus === "secure" ? (
                <CheckCircle className="w-4 h-4 text-green-500" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-yellow-500" />
              )}
              <span className="font-medium">
                {summary.security_status?.message || "Status unknown"}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  };

  // Show empty state when no domain is provided
  if (!domain) {
    return (
      <div className="min-h-screen  p-8">
        <div className="max-w-6xl mx-auto">
          <div className="text-center">
            <p className="text-white-600">
              Enter a domain name to analyze its DNSSEC chain
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen p-8">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-8">
            <p className="text-white-600">
              Analyzing DNSSEC chain for{" "}
              <span className="font-mono bg-gray-100 px-2 py-1 rounded">
                {domain}
              </span>
            </p>
          </div>
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="min-h-screen p-8">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-8">
            <p className="text-white-600">
              Error analyzing DNSSEC chain for{" "}
              <span className="font-mono bg-gray-100 px-2 py-1 rounded">
                {domain}
              </span>
            </p>
          </div>
          <div className="flex items-center justify-center">
            <Card className="w-96">
              <CardContent className="p-6 text-center">
                <XCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-white-900 mb-2">
                  Error Loading Data
                </h3>
                <p className="text-gray-600 mb-4">{error}</p>
                <button
                  onClick={fetchDNSSECData}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Retry
                </button>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen  p-8">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-8">
          <p className="text-white-600">
            Analyzing DNSSEC chain for{" "}
            <span className="font-mono bg-gray-100 px-2 py-1 rounded">
              {data?.metadata?.target_domain || domain}
            </span>
          </p>
          {error && (
            <div className="mt-2 text-sm text-yellow-600 bg-yellow-50 px-3 py-1 rounded-lg inline-block">
              Using fallback data due to API error: {error}
            </div>
          )}
        </div>

        {data?.chain_summary && <ChainSummary summary={data.chain_summary} />}

        <div className="flex flex-col items-center space-y-12">
          {data?.levels?.map((level, index) => (
            <DomainBox
              key={level.id || index}
              level={level}
              index={index}
              total={data.levels.length}
              levels={data.levels}
            />
          ))}
        </div>

        {/* Metadata Footer */}
        <div className="mt-12 text-center text-sm text-gray-500">
          <p>
            Analysis performed on{" "}
            {data?.metadata?.analysis_timestamp
              ? new Date(data.metadata.analysis_timestamp).toLocaleString()
              : new Date().toLocaleString()}
          </p>
        </div>
      </div>
    </div>
  );
}

export default DNSSECVisualizer;
