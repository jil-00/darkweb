#!/usr/bin/env python
"""Test the new unified enrichment endpoint with 4 separate scores."""

import httpx
import asyncio
import json
from datetime import datetime

async def test_unified_enrichment():
    """Test the unified enrichment endpoint."""
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # First, try to register a test user
            register_response = await client.post(
                "http://localhost:8000/api/v1/auth/register",
                json={"email": "test@example.com", "password": "test123456"}
            )
            
            if register_response.status_code not in (200, 409):  # 409 means user exists
                print(f"Register failed: {register_response.status_code}")
                print(register_response.text)
            
            # Now login
            login_response = await client.post(
                "http://localhost:8000/api/v1/auth/login",
                json={"email": "test@example.com", "password": "test123456"}
            )
            
            if login_response.status_code != 200:
                print(f"Login failed: {login_response.status_code}")
                print(login_response.text)
                return
            
            token = login_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            # Now test with 8.8.8.8 (Google DNS) - should have HIGH exposure but LOW threat
            response = await client.post(
                "http://localhost:8000/api/v1/threat-intel/unified-enrich",
                params={"ioc_value": "8.8.8.8"},
                headers=headers
            )
            
            if response.status_code == 200:
                report = response.json()
                
                print("=" * 80)
                print("UNIFIED THREAT INTELLIGENCE REPORT")
                print("=" * 80)
                print(f"IOC: {report.get('ioc_value')}")
                print(f"IOC Type: {report.get('ioc_type')}")
                print()
                
                print("SCORING BREAKDOWN:")
                print("-" * 80)
                print(f"  Exposure Score:    {report.get('exposure_score', 'N/A'):.1f}/100")
                print(f"  Threat Score:      {report.get('threat_score', 'N/A'):.1f}/100")
                print(f"  Reputation Status: {report.get('reputation_status', 'N/A')}")
                print(f"  Confidence Score:  {report.get('confidence_score', 'N/A')*100:.0f}%")
                print(f"  Risk Level:        {report.get('risk_level', 'N/A')}")
                print()
                
                # Show explanations
                if 'exposure_reasoning' in report and report['exposure_reasoning']:
                    exp_reasoning = report['exposure_reasoning']
                    print("EXPOSURE ANALYSIS:")
                    print(f"  Reasoning: {exp_reasoning.get('reasoning', 'N/A')}")
                    if exp_reasoning.get('key_factors'):
                        print(f"  Key Factors: {', '.join(exp_reasoning['key_factors'])}")
                    print()
                
                if 'threat_reasoning' in report and report['threat_reasoning']:
                    threat_reasoning = report['threat_reasoning']
                    print("THREAT ANALYSIS:")
                    print(f"  Reasoning: {threat_reasoning.get('reasoning', 'N/A')}")
                    if threat_reasoning.get('key_factors'):
                        print(f"  Key Factors: {', '.join(threat_reasoning['key_factors'])}")
                    print()
                
                if 'reputation_reasoning' in report and report['reputation_reasoning']:
                    print("REPUTATION ASSESSMENT:")
                    print(f"  {report['reputation_reasoning']}")
                    print()
                
                # Validate the key requirement: HIGH exposure but LOW threat for trusted infrastructure
                exposure = report.get('exposure_score', 0)
                threat = report.get('threat_score', 0)
                reputation = report.get('reputation_status', '')
                
                print("VALIDATION:")
                print("-" * 80)
                print(f"✓ Exposure score is HIGH: {exposure > 50}")
                print(f"✓ Threat score is LOW: {threat < 20}")
                print(f"✓ Reputation is Enterprise: {'Enterprise' in reputation or 'Trusted' in reputation}")
                print()
                
                if exposure > 50 and threat < 20 and 'Enterprise' in reputation:
                    print("✓ SUCCESS: Exposure correctly separated from Threat!")
                    print("✓ 8.8.8.8 shows HIGH exposure but LOW threat (as expected)")
                else:
                    print("✗ FAILED: Scores not separated correctly")
                
            else:
                print(f"Error: {response.status_code}")
                print(response.text)
                
        except Exception as e:
            print(f"Exception: {e}")

if __name__ == "__main__":
    asyncio.run(test_unified_enrichment())
