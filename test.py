#!/usr/bin/env python3
"""
DNSSEC Chain of Trust Analyzer
Analyzes and displays the complete DNSSEC chain of trust for a domain,
including DS records, DNSKEY records, and detailed cryptographic information.
"""

import dns.resolver
import dns.name
import dns.rdatatype
import dns.dnssec
import dns.message
import dns.query
import socket
import sys
import argparse
import json
import datetime
from typing import List, Dict, Any, Optional, Tuple
import binascii
import hashlib
import base64

class DNSSECAnalyzer:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.use_edns(0, dns.flags.DO, 4096)
        
    def get_algorithm_name(self, alg_num: int) -> str:
        """Convert algorithm number to human-readable name"""
        algorithms = {
            1: "RSAMD5",
            3: "DSA",
            5: "RSASHA1",
            6: "DSA-NSEC3-SHA1",
            7: "RSASHA1-NSEC3-SHA1",
            8: "RSASHA256",
            10: "RSASHA512",
            12: "ECC-GOST",
            13: "ECDSAP256SHA256",
            14: "ECDSAP384SHA384",
            15: "ED25519",
            16: "ED448"
        }
        return algorithms.get(alg_num, f"Unknown({alg_num})")
    
    def get_digest_type_name(self, digest_type: int) -> str:
        """Convert digest type number to human-readable name"""
        digest_types = {
            1: "SHA-1",
            2: "SHA-256",
            3: "GOST R 34.11-94",
            4: "SHA-384"
        }
        return digest_types.get(digest_type, f"Unknown({digest_type})")
    
    def format_key_data(self, key_data: bytes) -> str:
        """Format key data for display"""
        b64_data = base64.b64encode(key_data).decode()
        # Split into 64-character lines
        lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
        return '\n                '.join(lines)
    
    def get_key_size(self, key_data: bytes, algorithm: int) -> int:
        """Estimate key size based on key data and algorithm"""
        if algorithm in [5, 7, 8, 10]:  # RSA algorithms
            # For RSA, key size is roughly the bit length of the modulus
            # This is a rough estimation
            return len(key_data) * 8 // 10  # Approximate
        elif algorithm in [13, 14]:  # ECDSA
            if algorithm == 13:  # P-256
                return 256
            elif algorithm == 14:  # P-384
                return 384
        elif algorithm == 15:  # Ed25519
            return 255
        elif algorithm == 16:  # Ed448
            return 448
        return len(key_data) * 8
    
    def query_with_dnssec(self, domain: str, record_type: str) -> Optional[dns.message.Message]:
        """Query DNS with DNSSEC validation"""
        try:
            query = dns.message.make_query(domain, record_type, want_dnssec=True)
            query.flags |= dns.flags.AD
            
            # Try multiple nameservers
            nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            
            for ns in nameservers:
                try:
                    response = dns.query.udp(query, ns, timeout=10)
                    if response:
                        return response
                except Exception:
                    continue
                    
            return None
        except Exception as e:
            print(f"Error querying {domain} {record_type}: {e}")
            return None
    
    def get_ds_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get DS records for a domain"""
        ds_records = []
        try:
            response = self.query_with_dnssec(domain, 'DS')
            if not response:
                return ds_records
                
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DS:
                    for rdata in rrset:
                        ds_records.append({
                            'key_tag': rdata.key_tag,
                            'algorithm': rdata.algorithm,
                            'algorithm_name': self.get_algorithm_name(rdata.algorithm),
                            'digest_type': rdata.digest_type,
                            'digest_type_name': self.get_digest_type_name(rdata.digest_type),
                            'digest': binascii.hexlify(rdata.digest).decode().upper(),
                            'ttl': rrset.ttl
                        })
        except Exception as e:
            print(f"Error getting DS records for {domain}: {e}")
        
        return ds_records
    
    def get_dnskey_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get DNSKEY records for a domain"""
        dnskey_records = []
        try:
            response = self.query_with_dnssec(domain, 'DNSKEY')
            if not response:
                return dnskey_records
                
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    for rdata in rrset:
                        key_size = self.get_key_size(rdata.key, rdata.algorithm)
                        key_tag = dns.dnssec.key_id(rdata)
                        
                        dnskey_records.append({
                            'flags': rdata.flags,
                            'protocol': rdata.protocol,
                            'algorithm': rdata.algorithm,
                            'algorithm_name': self.get_algorithm_name(rdata.algorithm),
                            'key_tag': key_tag,
                            'key_size': key_size,
                            'key_data': rdata.key,
                            'key_data_b64': self.format_key_data(rdata.key),
                            'is_sep': bool(rdata.flags & 1),  # Secure Entry Point
                            'is_zsk': not bool(rdata.flags & 1),  # Zone Signing Key
                            'ttl': rrset.ttl
                        })
        except Exception as e:
            print(f"Error getting DNSKEY records for {domain}: {e}")
        
        return dnskey_records
    
    def get_ns_records(self, domain: str) -> List[str]:
        """Get NS records for a domain"""
        ns_records = []
        try:
            response = self.query_with_dnssec(domain, 'NS')
            if not response:
                return ns_records
                
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.NS:
                    for rdata in rrset:
                        ns_records.append(str(rdata.target))
        except Exception as e:
            print(f"Error getting NS records for {domain}: {e}")
        
        return ns_records
    
    def get_soa_records(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get SOA record for a domain"""
        try:
            response = self.query_with_dnssec(domain, 'SOA')
            if not response:
                return None
                
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    rdata = rrset[0]
                    return {
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum,
                        'ttl': rrset.ttl
                    }
        except Exception as e:
            print(f"Error getting SOA record for {domain}: {e}")
        
        return None
    
    def build_chain_of_trust(self, domain: str) -> List[Dict[str, Any]]:
        """Build the complete DNSSEC chain of trust from root to domain"""
        # First, build the hierarchy from domain to root
        hierarchy = []
        current_domain = dns.name.from_text(domain)
        
        # Build the full hierarchy including the target domain
        while len(current_domain) >= 0:
            domain_str = str(current_domain).rstrip('.')
            
            # Add root domain
            if not domain_str:
                hierarchy.append('.')
                break
            else:
                hierarchy.append(domain_str)
            
            # Move to parent domain
            if len(current_domain) == 0:
                break
            current_domain = current_domain.parent()
        
        # Reverse to get root -> TLD -> domain order
        hierarchy.reverse()
        
        chain = []
        for domain_str in hierarchy:
            print(f"Analyzing: {domain_str if domain_str != '.' else 'ROOT'}")
            
            # Get all relevant records
            ds_records = self.get_ds_records(domain_str)
            dnskey_records = self.get_dnskey_records(domain_str)
            ns_records = self.get_ns_records(domain_str)
            soa_record = self.get_soa_records(domain_str)
            
            chain.append({
                'domain': domain_str,
                'display_name': 'ROOT' if domain_str == '.' else domain_str,
                'ds_records': ds_records,
                'dnskey_records': dnskey_records,
                'ns_records': ns_records,
                'soa_record': soa_record
            })
        
        return chain
    
    def create_json_output(self, chain: List[Dict[str, Any]], target_domain: str) -> Dict[str, Any]:
        """Create a comprehensive JSON structure for frontend consumption"""
        
        # Process each level in the chain
        levels = []
        for i, level in enumerate(chain):
            domain = level['domain']
            display_name = level['display_name']
            
            # Determine domain type
            domain_type = "root"
            if domain == '.':
                domain_type = "root"
            elif i == 1 and len(chain) > 2:
                domain_type = "tld"
            elif i == len(chain) - 1 and i > 0:
                domain_type = "target"
            else:
                domain_type = "subdomain"
            
            # Calculate DNSSEC status
            has_ds = bool(level['ds_records'])
            has_dnskey = bool(level['dnskey_records'])
            
            if domain == '.':  # Root zone special case
                status = "signed" if has_dnskey else "unsigned"
                status_message = "Root zone is signed (trust anchor)" if has_dnskey else "Root zone DNSKEY not found"
                status_type = "success" if has_dnskey else "error"
            elif has_ds and has_dnskey:
                status = "signed"
                status_message = "Fully signed with DNSSEC"
                status_type = "success"
            elif has_dnskey:
                status = "partial"
                status_message = "Has DNSKEY but no DS record (unsigned delegation)"
                status_type = "warning"
            elif has_ds:
                status = "partial"
                status_message = "Has DS record but no DNSKEY found"
                status_type = "warning"
            else:
                status = "unsigned"
                status_message = "No DNSSEC records found"
                status_type = "error"
            
            # Create level object
            level_obj = {
                "id": f"level_{i}",
                "index": i,
                "domain": domain,
                "display_name": display_name,
                "domain_type": domain_type,
                "dnssec_status": {
                    "status": status,
                    "message": status_message,
                    "type": status_type,
                    "has_ds": has_ds,
                    "has_dnskey": has_dnskey
                },
                "records": {
                    "ds_records": level['ds_records'],
                    "dnskey_records": level['dnskey_records'],
                    "ns_records": level['ns_records'],
                    "soa_record": level['soa_record']
                },
                "delegation": {
                    "delegates_to": chain[i + 1]['display_name'] if i < len(chain) - 1 else None,
                    "delegated_from": chain[i - 1]['display_name'] if i > 0 else None
                }
            }
            levels.append(level_obj)
        
        # Calculate summary statistics
        signed_levels = sum(1 for level in chain if level['dnskey_records'])
        total_levels = len(chain)
        
        # Check for broken chain
        chain_status = "complete"
        chain_message = "Full DNSSEC validation possible"
        
        broken_chain = False
        for i, level in enumerate(chain[:-1]):  # All except last
            current_has_ds = bool(level['ds_records'])
            if level['domain'] != '.' and not current_has_ds:  # Skip root for DS check
                broken_chain = True
                break
        
        if broken_chain:
            chain_status = "broken"
            chain_message = "Missing DS records in delegation"
        elif signed_levels < total_levels:
            chain_status = "incomplete"
            chain_message = "Some levels unsigned"
        
        # Create relationships for graph visualization
        relationships = []
        for i in range(len(levels) - 1):
            current_level = levels[i]
            next_level = levels[i + 1]
            
            # Determine relationship type based on DS records
            relationship_type = "delegation"
            relationship_status = "valid"
            
            if current_level['dnssec_status']['has_ds'] or current_level['domain_type'] == 'root':
                if next_level['dnssec_status']['has_dnskey']:
                    relationship_status = "valid"
                else:
                    relationship_status = "broken"
            else:
                relationship_status = "unsigned"
            
            relationships.append({
                "id": f"rel_{i}",
                "from": current_level['id'],
                "to": next_level['id'],
                "from_domain": current_level['display_name'],
                "to_domain": next_level['display_name'],
                "type": relationship_type,
                "status": relationship_status
            })
        
        # Create comprehensive JSON structure
        result = {
            "metadata": {
                "target_domain": target_domain,
                "analysis_timestamp": datetime.datetime.now().isoformat(),
                "chain_length": total_levels,
                "signed_levels": signed_levels,
                "chain_status": chain_status,
                "chain_message": chain_message
            },
            "chain_summary": {
                "total_levels": total_levels,
                "signed_levels": signed_levels,
                "unsigned_levels": total_levels - signed_levels,
                "chain_complete": chain_status == "complete",
                "security_status": {
                    "overall_status": chain_status,
                    "message": chain_message,
                    "type": "success" if chain_status == "complete" else "warning" if chain_status == "incomplete" else "error"
                }
            },
            "levels": levels,
            "relationships": relationships,
            "graph_data": {
                "nodes": [
                    {
                        "id": level['id'],
                        "label": level['display_name'],
                        "domain": level['domain'],
                        "type": level['domain_type'],
                        "status": level['dnssec_status']['status'],
                        "status_type": level['dnssec_status']['type'],
                        "has_ds": level['dnssec_status']['has_ds'],
                        "has_dnskey": level['dnssec_status']['has_dnskey'],
                        "ds_count": len(level['records']['ds_records']),
                        "dnskey_count": len(level['records']['dnskey_records']),
                        "ns_count": len(level['records']['ns_records'])
                    }
                    for level in levels
                ],
                "edges": [
                    {
                        "id": rel['id'],
                        "source": rel['from'],
                        "target": rel['to'],
                        "label": f"{rel['from_domain']} → {rel['to_domain']}",
                        "type": rel['type'],
                        "status": rel['status'],
                        "animated": rel['status'] == "valid"
                    }
                    for rel in relationships
                ]
            }
        }
        print(result)
        return result
    
    def print_chain_analysis(self, chain: List[Dict[str, Any]]):
        """Print detailed analysis of the DNSSEC chain"""
        print("\n" + "="*80)
        print("DNSSEC CHAIN OF TRUST ANALYSIS")
        print("From ROOT → TLD → DOMAIN")
        print("="*80)
        
        for i, level in enumerate(chain):
            domain = level['domain']
            display_name = level['display_name']
            
            print(f"\n{'─'*60}")
            if domain == '.':
                print(f"LEVEL {i+1}: {display_name} (DNS Root Zone)")
            else:
                domain_type = ""
                if i == 1 and len(chain) > 2:  # TLD level
                    domain_type = " (Top Level Domain)"
                elif i == len(chain) - 1 and i > 1:  # Final domain
                    domain_type = " (Target Domain)"
                print(f"LEVEL {i+1}: {display_name.upper()}{domain_type}")
            print(f"{'─'*60}")
            
            # Print NS Records
            if level['ns_records']:
                print(f"\n📍 NAME SERVERS:")
                for ns in level['ns_records']:
                    print(f"   • {ns}")
            
            # Print SOA Record
            if level['soa_record']:
                soa = level['soa_record']
                print(f"\n📋 SOA RECORD:")
                print(f"   Master:     {soa['mname']}")
                print(f"   Contact:    {soa['rname']}")
                print(f"   Serial:     {soa['serial']}")
                print(f"   Refresh:    {soa['refresh']}s")
                print(f"   Retry:      {soa['retry']}s")
                print(f"   Expire:     {soa['expire']}s")
                print(f"   Minimum:    {soa['minimum']}s")
                print(f"   TTL:        {soa['ttl']}s")
            
            # Print DS Records
            if level['ds_records']:
                print(f"\n🔗 DS RECORDS (Delegation Signer):")
                for j, ds in enumerate(level['ds_records'], 1):
                    print(f"   DS Record #{j}:")
                    print(f"     Key Tag:      {ds['key_tag']}")
                    print(f"     Algorithm:    {ds['algorithm']} ({ds['algorithm_name']})")
                    print(f"     Digest Type:  {ds['digest_type']} ({ds['digest_type_name']})")
                    print(f"     Digest:       {ds['digest']}")
                    print(f"     TTL:          {ds['ttl']}s")
                    print()
            else:
                if domain != '.':  # Root doesn't have DS records
                    print(f"\n🔗 DS RECORDS: None found")
            
            # Print DNSKEY Records
            if level['dnskey_records']:
                print(f"\n🔑 DNSKEY RECORDS:")
                for j, key in enumerate(level['dnskey_records'], 1):
                    key_type = "KSK (Key Signing Key)" if key['is_sep'] else "ZSK (Zone Signing Key)"
                    print(f"   DNSKEY Record #{j} - {key_type}:")
                    print(f"     Key Tag:      {key['key_tag']}")
                    print(f"     Flags:        {key['flags']} ({'SEP' if key['is_sep'] else 'No SEP'})")
                    print(f"     Protocol:     {key['protocol']}")
                    print(f"     Algorithm:    {key['algorithm']} ({key['algorithm_name']})")
                    print(f"     Key Size:     ~{key['key_size']} bits")
                    print(f"     TTL:          {key['ttl']}s")
                    print(f"     Public Key:   {key['key_data_b64']}")
                    print()
            else:
                print(f"\n🔑 DNSKEY RECORDS: None found")
            
            # Validation status
            has_ds = bool(level['ds_records'])
            has_dnskey = bool(level['dnskey_records'])
            
            print(f"\n🔍 DNSSEC STATUS:")
            if domain == '.':  # Root zone special case
                if has_dnskey:
                    print(f"   ✅ Root zone is signed (trust anchor)")
                else:
                    print(f"   ❌ Root zone DNSKEY not found")
            elif has_ds and has_dnskey:
                print(f"   ✅ Fully signed with DNSSEC")
            elif has_dnskey:
                print(f"   ⚠️  Has DNSKEY but no DS record (unsigned delegation)")
            elif has_ds:
                print(f"   ⚠️  Has DS record but no DNSKEY found")
            else:
                print(f"   ❌ No DNSSEC records found")
            
            # Show chain relationship
            if i < len(chain) - 1:
                next_level = chain[i + 1]['display_name']
                print(f"\n🔗 DELEGATION TO: {next_level}")
        
        # Summary
        print(f"\n{'='*80}")
        print("CHAIN OF TRUST SUMMARY")
        print(f"{'='*80}")
        
        signed_levels = sum(1 for level in chain if level['dnskey_records'])
        total_levels = len(chain)
        
        print(f"📊 Chain Length:    {total_levels} levels")
        print(f"🔐 Signed Levels:   {signed_levels}/{total_levels}")
        
        # Check for broken chain
        broken_chain = False
        for i, level in enumerate(chain[:-1]):  # All except last
            current_has_ds = bool(level['ds_records'])
            next_has_dnskey = bool(chain[i+1]['dnskey_records'])
            
            if level['domain'] != '.' and not current_has_ds:  # Skip root for DS check
                broken_chain = True
                break
        
        if broken_chain:
            print(f"⚠️  Chain Status:   BROKEN - Missing DS records in delegation")
        elif signed_levels == total_levels:
            print(f"✅ Chain Status:   COMPLETE - Full DNSSEC validation possible")
        else:
            print(f"⚠️  Chain Status:   INCOMPLETE - Some levels unsigned")

def main():
    parser = argparse.ArgumentParser(description='Analyze DNSSEC chain of trust for a domain')
    parser.add_argument('domain', help='Domain name to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-j', '--json', action='store_true', help='Output JSON format for frontend consumption')
    parser.add_argument('-o', '--output', help='Output file for JSON data')
    
    args = parser.parse_args()
    
    # Normalize domain name
    domain = args.domain.lower().rstrip('.')
    
    if not args.json:
        print(f"🔍 Starting DNSSEC analysis for: {domain}")
        print(f"⏱️  This may take a few moments...")
    
    analyzer = DNSSECAnalyzer()
    
    try:
        chain = analyzer.build_chain_of_trust(domain)
        
        if not chain:
            if args.json:
                error_json = {
                    "error": "Could not build chain of trust",
                    "domain": domain,
                    "success": False
                }
                print(json.dumps(error_json, indent=2))
            else:
                print(f"❌ Could not build chain of trust for {domain}")
            sys.exit(1)
        
        if args.json:
            # Create JSON output for frontend
            json_data = analyzer.create_json_output(chain, domain)
            json_data["success"] = True
            
            if args.output:
                # Write to file
                with open(args.output, 'w') as f:
                    json.dump(json_data, f, indent=2)
                print(f"JSON data written to {args.output}")
            else:
                # Print to stdout
                print(json.dumps(json_data, indent=2))
        else:
            # Print human-readable analysis
            analyzer.print_chain_analysis(chain)
            
            print(f"\n{'='*80}")
            print("ANALYSIS COMPLETE")
            print(f"Analyzed {len(chain)} levels in the chain of trust")
            print("Chain order: ROOT → TLD → DOMAIN")
            print("\n💡 TIP: Use --json flag to get machine-readable output for frontend integration")
            print("="*80)
        
    except KeyboardInterrupt:
        if not args.json:
            print("\n⏹️  Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        if args.json:
            error_json = {
                "error": str(e),
                "domain": domain,
                "success": False
            }
            print(json.dumps(error_json, indent=2))
        else:
            print(f"❌ Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()