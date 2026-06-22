"""
mitmproxy addon to capture HTTP traffic to s13.iremovalpro.com
This addon logs all requests/responses to JSON files for analysis.
"""
import json
import os
import sys
from datetime import datetime
from mitmproxy import http, ctx
from mitmproxy.net.http.http1.assemble import assemble_request_head, assemble_response_head

class IRemovalCapture:
    """Capture all iRemoval PRO HTTP traffic"""

    def __init__(self):
        self.outdir = r'C:\Temp\mitmproxy_out'
        os.makedirs(self.outdir, exist_ok=True)
        self.flows = []
        self.counter = 0

    def request(self, flow: http.HTTPFlow):
        """Log all requests going to iRemoval servers"""
        host = flow.request.pretty_host
        if 'iremovalpro' in host or 'albert.apple' in host:
            self.counter += 1
            ts = datetime.now().isoformat()
            entry = {
                'idx': self.counter,
                'ts': ts,
                'direction': 'request',
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'host': host,
                'headers': dict(flow.request.headers),
                'body': flow.request.content.decode('utf-8', errors='replace') if flow.request.content else None,
            }
            self.flows.append(entry)
            print(f'\n[REQ #{self.counter}] {flow.request.method} {flow.request.pretty_url}')
            print(f'  Headers: {dict(flow.request.headers)}')
            if flow.request.content:
                body = flow.request.content.decode('utf-8', errors='replace')
                print(f'  Body: {body[:2000]}')
                if len(body) > 2000:
                    print(f'  ... [{len(body)} bytes total]')

    def response(self, flow: http.HTTPFlow):
        """Log all responses from iRemoval servers"""
        host = flow.request.pretty_host
        if 'iremovalpro' in host or 'albert.apple' in host:
            ts = datetime.now().isoformat()
            entry = {
                'idx': self.counter,
                'ts': ts,
                'direction': 'response',
                'status': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': flow.response.content.decode('utf-8', errors='replace') if flow.response.content else None,
            }
            self.flows.append(entry)
            print(f'\n[RES #{self.counter}] {flow.response.status_code} {flow.request.pretty_url}')
            print(f'  Headers: {dict(flow.response.headers)}')
            if flow.response.content:
                body = flow.response.content.decode('utf-8', errors='replace')
                print(f'  Body: {body[:2000]}')
                if len(body) > 2000:
                    print(f'  ... [{len(body)} bytes total]')

    def done(self):
        """Save all flows to disk on exit"""
        outfile = os.path.join(self.outdir, 'iremo_capture.json')
        with open(outfile, 'w', encoding='utf-8') as f:
            json.dump(self.flows, f, indent=2, ensure_ascii=False)
        print(f'\n[*] Saved {len(self.flows)} flows to {outfile}')

addons = [IRemovalCapture()]
