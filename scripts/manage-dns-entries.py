#!/usr/bin/env python3

import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.error

def get_config():
    epilog_text = """
Examples:
  # List all DNS entries
  %(prog)s list

  # Add a new DNS entry using environment variables for authentication
  %(prog)s add -d example.com -a 192.168.1.10

  # Set a DNS entry (adds if missing, updates if already exists)
  %(prog)s set -d example.com -a 192.168.1.10

  # Update an existing DNS entry by specifying its current IP
  %(prog)s update -d example.com -a 192.168.1.10 -na 192.168.1.20

  # Delete a DNS entry by specifying credentials inline
  %(prog)s -u http://192.168.1.2 -U admin -P secret delete -d example.com -a 192.168.1.10
"""
    parser = argparse.ArgumentParser(
        description="Manage AdGuard Home custom DNS overrides (rewrites).",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Define connection arguments
    parser.add_argument('-u', '--url', help="URL of the AdGuard Home instance (fallback: AGH_URL env var)")
    parser.add_argument('-U', '--user', help="Username for authentication (fallback: AGH_USER env var)")
    parser.add_argument('-P', '--password', help="Password for authentication (fallback: AGH_PASSWORD env var)")
    
    # Define subcommands
    subparsers = parser.add_subparsers(dest='action', required=True, help="Action to perform")
    
    # List action
    parser_list = subparsers.add_parser('list', help="List all DNS entries")
    
    # Add action
    parser_add = subparsers.add_parser('add', help="Add a new DNS entry")
    parser_add.add_argument('-d', '--domain', required=True, help="Domain for the DNS entry")
    parser_add.add_argument('-a', '--answer', required=True, help="Answer/IP for the DNS entry")
    
    # Set action (Upsert)
    parser_set = subparsers.add_parser('set', help="Set a DNS entry (adds if missing, updates if already exists)")
    parser_set.add_argument('-d', '--domain', required=True, help="Domain for the DNS entry")
    parser_set.add_argument('-a', '--answer', required=True, help="Target answer/IP for the DNS entry")
    
    # Update action
    parser_update = subparsers.add_parser('update', help="Update an existing DNS entry")
    parser_update.add_argument('-d', '--domain', required=True, help="Current domain for the DNS entry to update")
    parser_update.add_argument('-a', '--answer', required=True, help="Current answer/IP for the DNS entry to update")
    parser_update.add_argument('-nd', '--new-domain', help="New domain (defaults to current if omitted)")
    parser_update.add_argument('-na', '--new-answer', help="New answer/IP (defaults to current if omitted)")
    
    # Delete action
    parser_delete = subparsers.add_parser('delete', help="Delete a DNS entry")
    parser_delete.add_argument('-d', '--domain', required=True, help="Domain for the DNS entry")
    parser_delete.add_argument('-a', '--answer', required=True, help="Answer/IP for the DNS entry")
    
    args = parser.parse_args()
    
    url = args.url or os.environ.get('AGH_URL')
    user = args.user or os.environ.get('AGH_USER')
    password = args.password or os.environ.get('AGH_PASSWORD')
    
    if not url:
        sys.exit("Error: URL is not specified. Use --url or AGH_URL environment variable.")
    if not user:
        sys.exit("Error: Username is not specified. Use --user or AGH_USER environment variable.")
    if not password:
        sys.exit("Error: Password is not specified. Use --password or AGH_PASSWORD environment variable.")
        
    return {
        'url': url.rstrip('/'),
        'user': user,
        'password': password,
        'action': args.action,
        'domain': getattr(args, 'domain', None),
        'answer': getattr(args, 'answer', None),
        'new_domain': getattr(args, 'new_domain', None),
        'new_answer': getattr(args, 'new_answer', None)
    }

def make_request(cfg, endpoint, payload=None, method=None):
    url = f"{cfg['url']}/{endpoint}"
    
    data = None
    if payload:
        data = json.dumps(payload).encode('utf-8')
        
    req = urllib.request.Request(url, data=data, method=method)
    
    # Adding Basic Auth securely
    auth_str = f"{cfg['user']}:{cfg['password']}"
    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    req.add_header("Authorization", f"Basic {auth_b64}")
    
    if payload:
        req.add_header("Content-Type", "application/json")
        
    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode('utf-8').strip()
            if res_body:
                try:
                    return json.loads(res_body)
                except json.JSONDecodeError:
                    return res_body
            return None
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='ignore').strip()
        sys.exit(f"HTTP Error {e.code}: {err_body}")
    except urllib.error.URLError as e:
        sys.exit(f"URL Error: {e.reason}")

def main():
    cfg = get_config()
    
    if cfg['action'] == 'list':
        result = make_request(cfg, "control/rewrite/list")
        if isinstance(result, str):
            print(result)
        else:
            print(json.dumps(result, indent=2))
            
    elif cfg['action'] == 'add':
        payload = {"domain": cfg['domain'], "answer": cfg['answer']}
        result = make_request(cfg, "control/rewrite/add", payload)
        print(f"Successfully added DNS entry: {cfg['domain']} -> {cfg['answer']}")
        if result and result != "OK":
            print(f"Response: {result}")
            
    elif cfg['action'] == 'set':
        target_domain = cfg['domain']
        target_answer = cfg['answer']
        
        # Fetch current list
        existing_entries = make_request(cfg, "control/rewrite/list")
        if not isinstance(existing_entries, list):
            existing_entries = []
            
        matching_entries = [e for e in existing_entries if e.get('domain') == target_domain]
        
        if not matching_entries:
            # 1. Add if missing
            payload = {"domain": target_domain, "answer": target_answer}
            make_request(cfg, "control/rewrite/add", payload)
            print(f"Set: Created new DNS entry: {target_domain} -> {target_answer}")
            
        elif len(matching_entries) == 1:
            # 2. Update if exactly one exists
            current_answer = matching_entries[0].get('answer')
            if current_answer == target_answer:
                print(f"Set: DNS entry for '{target_domain}' already points to '{target_answer}'. No changes needed.")
            else:
                payload = {
                    "target": {"domain": target_domain, "answer": current_answer},
                    "update": {"domain": target_domain, "answer": target_answer}
                }
                make_request(cfg, "control/rewrite/update", payload, method="PUT")
                print(f"Set: Updated DNS entry '{target_domain}' from {current_answer} -> {target_answer}")
                
        else:
            # 3. Handle multiple existing entries (cleanup edge case)
            print(f"Set: Found {len(matching_entries)} existing entries for '{target_domain}'. Cleaning up to set single IP...")
            for entry in matching_entries:
                payload = {"domain": entry['domain'], "answer": entry['answer']}
                make_request(cfg, "control/rewrite/delete", payload)
            
            # Now add the correct one
            payload = {"domain": target_domain, "answer": target_answer}
            make_request(cfg, "control/rewrite/add", payload)
            print(f"Set: Recreated DNS entry: {target_domain} -> {target_answer}")
            
    elif cfg['action'] == 'update':
        payload = {
            "target": {
                "domain": cfg['domain'],
                "answer": cfg['answer']
            },
            "update": {
                "domain": cfg['new_domain'] if cfg['new_domain'] else cfg['domain'],
                "answer": cfg['new_answer'] if cfg['new_answer'] else cfg['answer']
            }
        }
        result = make_request(cfg, "control/rewrite/update", payload, method="PUT")
        print(f"Successfully updated DNS entry: {cfg['domain']} -> {cfg['answer']} to {payload['update']['domain']} -> {payload['update']['answer']}")
        if result and result != "OK":
            print(f"Response: {result}")
            
    elif cfg['action'] == 'delete':
        payload = {"domain": cfg['domain'], "answer": cfg['answer']}
        result = make_request(cfg, "control/rewrite/delete", payload)
        print(f"Successfully deleted DNS entry: {cfg['domain']} -> {cfg['answer']}")
        if result and result != "OK":
            print(f"Response: {result}")

if __name__ == "__main__":
    main()
