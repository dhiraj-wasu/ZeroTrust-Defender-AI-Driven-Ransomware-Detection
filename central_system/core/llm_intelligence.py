import logging
import json
import asyncio
from typing import Dict, Any, List
from models.schemas import LLMAnalysis, ThreatAlert
from config.settings import settings

class LLMIntelligence:
    """
    Multi-fallback LLM Intelligence System
    Fallback order: Gemini → OpenAI → Local Simulation
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.llm_config = settings.get_llm_config()
        self.threat_patterns = self._load_threat_patterns()
        self.available_providers = self._detect_available_providers()
        
        self.logger.info(f"Available LLM Providers: {self.available_providers}")
        self.logger.info(f"Fallback order: {self.llm_config['fallback_order']}")

    def _detect_available_providers(self) -> List[str]:
        """Detect which LLM providers are available and configured"""
        available = []
        
        # Check Gemini
        if self._is_gemini_available():
            available.append("gemini")
            self.logger.info("✅ Gemini: Available and configured")
        
        # Check OpenAI
        if self._is_openai_available():
            available.append("openai")
            self.logger.info("✅ OpenAI: Available and configured")
        
        # Local simulation is always available
        available.append("local")
        self.logger.info("✅ Local: Simulation mode always available")
        
        return available

    def _is_gemini_available(self) -> bool:
        """Check if Gemini is properly configured"""
        try:
            import google.generativeai as genai
            if not self.llm_config.get("gemini_api_key"):
                self.logger.warning("❌ Gemini API key not configured")
                return False
            
            # Test configuration
            genai.configure(api_key=self.llm_config["gemini_api_key"])
            
            # Try to list models to verify API key
            try:
                models = genai.list_models()
                gemini_models = [m.name for m in models if 'gemini' in m.name.lower()]
                if gemini_models:
                    self.logger.info(f"🔍 Found Gemini models: {len(gemini_models)}")
                return True
            except Exception as e:
                self.logger.warning(f"❌ Gemini API key validation failed: {e}")
                return False
                
        except ImportError:
            self.logger.warning("❌ google-generativeai not installed")
            return False
        except Exception as e:
            self.logger.warning(f"❌ Gemini configuration issue: {e}")
            return False

    def _is_openai_available(self) -> bool:
        """Check if OpenAI is properly configured"""
        try:
            import openai
            if not self.llm_config.get("openai_api_key"):
                self.logger.warning("❌ OpenAI API key not configured")
                return False
            
            # Check key format
            api_key = self.llm_config["openai_api_key"]
            if not api_key.startswith("sk-") or len(api_key) != 51:
                self.logger.warning("❌ OpenAI API key format invalid")
                return False
            
            return True
        except ImportError:
            self.logger.warning("❌ openai library not installed")
            return False
        except Exception as e:
            self.logger.warning(f"❌ OpenAI configuration issue: {e}")
            return False

    async def analyze_threat(self, alert: ThreatAlert, correlation_data: Dict[str, Any]) -> LLMAnalysis:
        """
        Perform LLM-powered threat analysis with multi-fallback
        Tries providers in order until one works
        """
        self.logger.info(f"🔍 Starting multi-fallback LLM analysis for {alert.agent_id}")
        
        # Try providers in fallback order
        for provider in self.llm_config['fallback_order']:
            if provider in self.available_providers:
                self.logger.info(f"🔄 Attempting analysis with {provider.upper()}")
                
                try:
                    if provider == "gemini":
                        result = await self._call_gemini_llm(alert, correlation_data)
                    elif provider == "openai":
                        result = await self._call_openai_llm(alert, correlation_data)
                    else:  # local
                        result = self._simulate_llm_analysis(alert, correlation_data)
                    
                    self.logger.info(f"✅ Successfully used {provider.upper()} for analysis")
                    return result
                    
                except Exception as e:
                    self.logger.warning(f"❌ {provider.upper()} analysis failed: {str(e)}")
                    # Remove failed provider from available list for this session
                    if provider in self.available_providers:
                        self.available_providers.remove(provider)
                    continue
        
        # If all providers fail, use ultimate fallback
        self.logger.error("💥 All LLM providers failed, using ultimate fallback")
        return self._ultimate_fallback_analysis(alert, correlation_data)

    async def _call_gemini_llm(self, alert: ThreatAlert, correlation_data: Dict[str, Any]) -> LLMAnalysis:
        """Call Google Gemini LLM for threat analysis with robust model selection"""
        try:
            import google.generativeai as genai
            
            # Configure Gemini
            genai.configure(api_key=self.llm_config["gemini_api_key"])
            
            # Try multiple model names in order
            model_names = [
                "models/gemini-2.0-flash",   # Most recent, fast and capable
                "models/gemini-2.0-pro",     # Higher quality tier
                "models/gemini-1.5-flash",
                "models/gemini-1.5-pro",
                "models/gemini-1.0-pro",
            ]
            
            model = None
            successful_model = None
            
            for model_name in model_names:
                try:
                    self.logger.info(f"🔄 Trying Gemini model: {model_name}")
                    model = genai.GenerativeModel(model_name)
                    
                    # Test with a simple prompt to verify it works
                    test_response = model.generate_content(
                        "Respond with 'OK'", 
                        generation_config=genai.types.GenerationConfig(max_output_tokens=10)
                    )
                    
                    successful_model = model_name
                    self.logger.info(f"✅ Successfully connected to Gemini model: {model_name}")
                    break
                    
                except Exception as e:
                    self.logger.debug(f"❌ Model {model_name} failed: {e}")
                    continue
            
            if model is None:
                # Final attempt: use any available model
                try:
                    models = genai.list_models()
                    for m in models:
                        if 'generateContent' in m.supported_generation_methods:
                            model = genai.GenerativeModel(m.name)
                            successful_model = m.name
                            self.logger.info(f"✅ Using available model: {m.name}")
                            break
                except Exception as e:
                    self.logger.error(f"❌ No working Gemini models found: {e}")
                    raise Exception(f"No working Gemini models available: {e}")
            
            if model is None:
                raise Exception("No Gemini models could be initialized")
            
            prompt = self._build_analysis_prompt(alert, correlation_data)
            
            # Generate content with proper configuration
            response = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        temperature=0.1,
                        max_output_tokens=1000,
                        top_p=0.8,
                        top_k=40
                    )
                )
            )
            
            llm_output = response.text
            self.logger.info(f"📊 Gemini analysis completed using model: {successful_model}")
            return self._parse_llm_response(llm_output)
            
        except Exception as e:
            self.logger.error(f"💥 Gemini API call failed: {e}")
            raise

    async def _call_openai_llm(self, alert: ThreatAlert, correlation_data: Dict[str, Any]) -> LLMAnalysis:
        """Call OpenAI LLM for threat analysis"""
        try:
            from openai import OpenAI
            
            client = OpenAI(api_key=self.llm_config["openai_api_key"])
            
            prompt = self._build_analysis_prompt(alert, correlation_data)
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity threat intelligence analyst. Analyze the provided threat data and provide structured assessment. Respond with valid JSON only."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            llm_output = response.choices[0].message.content
            self.logger.info("📊 OpenAI analysis completed successfully")
            return self._parse_llm_response(llm_output)
            
        except Exception as e:
            self.logger.error(f"💥 OpenAI API call failed: {e}")
            raise

    def _simulate_llm_analysis(self, alert: ThreatAlert, correlation: Dict[str, Any]) -> LLMAnalysis:
        """Simulate LLM analysis using advanced pattern matching"""
        self.logger.info("🔄 Running advanced simulated LLM analysis")
        
        forensic_data = alert.forensic_data
        file_patterns = forensic_data.get('file_access_patterns', {})
        network_connections = forensic_data.get('network_connections', [])
        system_metrics = forensic_data.get('system_metrics', {})
        
        # Advanced pattern-based classification
        encryption_detected = file_patterns.get('encryption_detected', False)
        ransom_note_found = file_patterns.get('ransom_note_found', False)
        files_modified = file_patterns.get('files_modified', 0)
        cpu_usage = system_metrics.get('cpu_usage', 0)
        
        # Network analysis
        smb_connections = [conn for conn in network_connections if 'SMB' in conn.get('protocol', '')]
        rdp_connections = [conn for conn in network_connections if 'RDP' in conn.get('protocol', '')]
        unknown_connections = [conn for conn in network_connections if conn.get('suspicious', False)]
        
        # Threat classification logic
        if encryption_detected and ransom_note_found:
            attack_class = "FAST_ENCRYPTION_RANSOMWARE"
            confidence = 0.95
            business_impact = "CRITICAL - Active ransomware encryption with ransom demand"
            recommended_response = "AGGRESSIVE_CONTAINMENT"
            
        elif encryption_detected and files_modified > 50:
            attack_class = "DATA_DESTRUCTION_WARE"
            confidence = 0.88
            business_impact = "HIGH - Mass file encryption without ransom note"
            recommended_response = "AGGRESSIVE_CONTAINMENT"
            
        elif smb_connections and files_modified > 10:
            attack_class = "LATERAL_MOVEMENT_RANSOMWARE"
            confidence = 0.85
            business_impact = "HIGH - Network propagation via SMB with file modifications"
            recommended_response = "TARGETED_CONTAINMENT"
            
        elif cpu_usage > 90 and any('mining' in conn.get('remote_host', '').lower() for conn in network_connections):
            attack_class = "CRYPTOMINER_MALWARE"
            confidence = 0.82
            business_impact = "MEDIUM - System resource theft for cryptocurrency mining"
            recommended_response = "TARGETED_CONTAINMENT"
            
        elif rdp_connections and unknown_connections:
            attack_class = "ADVANCED_PERSISTENT_THREAT"
            confidence = 0.78
            business_impact = "HIGH - Credential theft and lateral movement detected"
            recommended_response = "TARGETED_CONTAINMENT"
            
        elif files_modified > 5:
            attack_class = "DATA_EXFILTRATION_MALWARE"
            confidence = 0.70
            business_impact = "MEDIUM - Suspicious file access patterns"
            recommended_response = "ENHANCED_MONITORING"
            
        else:
            attack_class = "SUSPICIOUS_ACTIVITY"
            confidence = 0.60
            business_impact = "LOW - Unusual activity requiring investigation"
            recommended_response = "ENHANCED_MONITORING"

        # Propagation method analysis
        if smb_connections and rdp_connections:
            propagation = "MULTI_VECTOR_LATERAL_MOVEMENT"
        elif smb_connections:
            propagation = "SMB_NETWORK_PROPAGATION"
        elif rdp_connections:
            propagation = "RDP_CREDENTIAL_ATTACK"
        elif unknown_connections:
            propagation = "COVERT_CHANNEL_COMMUNICATION"
        else:
            propagation = "LOCAL_SYSTEM_INFECTION"

        # Compromise radius estimation
        related_agents = [alert.agent_id] + [a.get('agent_id', '') for a in correlation.get('related_alerts', [])]
        unique_agents = list(set([agent for agent in related_agents if agent]))
        
        if len(unique_agents) > 3:
            compromise_radius = f"WIDESPREAD: {alert.agent_id} + {len(unique_agents)-1} other systems"
        elif len(unique_agents) > 1:
            compromise_radius = f"LIMITED_SPREAD: {alert.agent_id} + {len(unique_agents)-1} other systems"
        else:
            compromise_radius = f"CONTAINED: {alert.agent_id} only"

        # Predict next targets based on attack pattern
        predicted_targets = self._predict_next_targets(alert, correlation)

        self.logger.info(f"✅ Simulated analysis complete: {attack_class} with {confidence:.1%} confidence")
        
        return LLMAnalysis(
            attack_classification=attack_class,
            propagation_method=propagation,
            estimated_compromise_radius=compromise_radius,
            business_impact=business_impact,
            confidence_score=confidence,
            recommended_network_response=recommended_response,
            predicted_next_targets=predicted_targets,
            llm_analysis_text=f"SIMULATED_ANALYSIS: {attack_class} - {business_impact}"
        )

    def _predict_next_targets(self, alert: ThreatAlert, correlation: Dict[str, Any]) -> List[str]:
        """Predict likely next targets based on attack patterns"""
        network_connections = alert.forensic_data.get('network_connections', [])
        connected_hosts = list(set([
            conn.get('remote_host') for conn in network_connections 
            if conn.get('remote_host') and conn.get('remote_host') != 'unknown'
        ]))
        
        # Department-based target prediction
        department = getattr(alert, 'department', 'default')
        department_targets = {
            "Finance": [
                "financial-database-server",
                "payment-processing-gateway", 
                "accounting-application-server",
                "budget-planning-system",
                "transaction-log-server"
            ],
            "IT": [
                "domain-controller-primary",
                "backup-storage-server",
                "network-shared-storage",
                "system-management-server",
                "security-monitoring-system"
            ],
            "HR": [
                "employee-records-database",
                "payroll-processing-server",
                "document-management-system",
                "benefits-administration-server",
                "recruitment-application-server"
            ],
            "Research": [
                "research-data-repository",
                "intellectual-property-server",
                "collaboration-platform",
                "experiment-data-storage",
                "project-management-server"
            ],
            "default": [
                "file-share-server",
                "backup-system-primary",
                "database-cluster-node",
                "email-server",
                "web-application-server"
            ]
        }
        
        # Combine connected hosts with department-specific targets
        predicted = connected_hosts[:3]  # Take first 3 connected hosts
        predicted.extend(department_targets.get(department, department_targets["default"])[:3])
        
        # Remove duplicates and limit to 5 targets
        unique_targets = list(set(predicted))
        return unique_targets[:5]

    def _ultimate_fallback_analysis(self, alert: ThreatAlert, correlation: Dict[str, Any]) -> LLMAnalysis:
        """Ultimate fallback when all LLM providers fail"""
        self.logger.warning("🛡️ Using ultimate fallback analysis")
        
        # Basic but reliable analysis based on threat level
        if alert.threat_level.value == 'critical':
            attack_class = "CRITICAL_THREAT_UNCERTAIN_TYPE"
            confidence = 0.75
            business_impact = "HIGH - Immediate containment required pending detailed analysis"
            recommended_response = "AGGRESSIVE_CONTAINMENT"
        elif alert.threat_level.value == 'high':
            attack_class = "HIGH_RISK_THREAT_UNCERTAIN_TYPE"
            confidence = 0.65
            business_impact = "MEDIUM - Investigation and containment needed"
            recommended_response = "TARGETED_CONTAINMENT"
        else:
            attack_class = "SUSPICIOUS_ACTIVITY_REQUIRES_ANALYSIS"
            confidence = 0.55
            business_impact = "LOW - Enhanced monitoring and analysis required"
            recommended_response = "ENHANCED_MONITORING"

        return LLMAnalysis(
            attack_classification=attack_class,
            propagation_method="UNKNOWN_PENDING_ANALYSIS",
            estimated_compromise_radius=f"{alert.agent_id} (assessment pending)",
            business_impact=business_impact,
            confidence_score=confidence,
            recommended_network_response=recommended_response,
            predicted_next_targets=[],
            llm_analysis_text="FALLBACK_ANALYSIS: LLM services unavailable - using threat level assessment"
        )

    def _build_analysis_prompt(self, alert: ThreatAlert, correlation: Dict[str, Any]) -> str:
        """Build detailed analysis prompt for LLM"""
        forensic_data = alert.forensic_data
        file_patterns = forensic_data.get('file_access_patterns', {})
        network_connections = forensic_data.get('network_connections', [])
        system_metrics = forensic_data.get('system_metrics', {})
        
        # Format network connections for readability
        unique_protocols = list(set(conn.get('protocol', 'UNKNOWN') for conn in network_connections))
        target_hosts = list(set(conn.get('remote_host', 'UNKNOWN') for conn in network_connections if conn.get('remote_host')))
        
        prompt = f"""
        CYBERSECURITY THREAT INTELLIGENCE ANALYSIS REQUEST

        CRITICAL INCIDENT DATA:
        - Incident ID: {getattr(alert, 'incident_id', 'UNKNOWN')}
        - Agent ID: {alert.agent_id}
        - Threat Level: {alert.threat_level.value}
        - Status: {alert.status}
        - Malware Process: {alert.malware_process or 'Unknown'}
        - Detection Confidence: {alert.detection_confidence}
        - Timestamp: {alert.timestamp}

        FORENSIC EVIDENCE SUMMARY:
        File System Activity:
        • Files Modified: {file_patterns.get('files_modified', 0)}
        • Encryption Detected: {file_patterns.get('encryption_detected', False)}
        • Ransom Note Found: {file_patterns.get('ransom_note_found', False)}
        • File Extensions Changed: {file_patterns.get('extensions_changed', [])}
        • Suspicious File Operations: {file_patterns.get('suspicious_operations', [])}

        Network Activity:
        • Total Connections: {len(network_connections)}
        • Protocols Used: {unique_protocols}
        • Target Hosts: {target_hosts[:5]} {f'(+{len(target_hosts)-5} more)' if len(target_hosts) > 5 else ''}
        • Suspicious Connections: {len([c for c in network_connections if c.get('suspicious', False)])}

        System Metrics:
        • CPU Usage: {system_metrics.get('cpu_usage', 0)}%
        • Memory Usage: {system_metrics.get('memory_usage', 0)}%
        • Disk Activity: {system_metrics.get('disk_activity', 'normal')}
        • Process Count: {system_metrics.get('process_count', 0)}

        CORRELATION INTELLIGENCE:
        • Related Alerts: {len(correlation.get('related_alerts', []))}
        • Attack Timeline Events: {len(correlation.get('attack_timeline', []))}
        • Propagation Attempts: {len(correlation.get('propagation_graph', {}).get('attempted_propagation', []))}
        • Correlation Confidence: {correlation.get('correlation_confidence', 0)}

        REQUIRED ANALYSIS OUTPUT:
        Provide a comprehensive threat assessment in the following JSON format:

        {{
            "attack_classification": "Specific threat classification (e.g., RANSOMWARE_TROJAN_COMBO, APT_LATERAL_MOVEMENT, etc.)",
            "propagation_method": "How the threat spreads (e.g., SMB_EXPLOITATION, RDP_BRUTE_FORCE, etc.)",
            "estimated_compromise_radius": "Scope of compromise (e.g., Single system, Department network, etc.)",
            "business_impact": "Impact level with description (e.g., CRITICAL - Data encryption and business disruption)",
            "confidence_score": 0.95,
            "recommended_network_response": "AGGRESSIVE_CONTAINMENT/TARGETED_CONTAINMENT/ENHANCED_MONITORING",
            "predicted_next_targets": ["target1", "target2", "target3"]
        }}

        ANALYSIS INSTRUCTIONS:
        1. Classify the specific attack type based on forensic evidence
        2. Identify the primary propagation method
        3. Estimate how far the threat has likely spread
        4. Assess business impact with specific reasoning
        5. Recommend appropriate containment response
        6. Predict the 3 most likely next targets

        Respond with valid JSON only.
        """

        return prompt

    def _parse_llm_response(self, llm_output: str) -> LLMAnalysis:
        """Parse LLM response into structured analysis"""
        try:
            # Clean the response and extract JSON
            cleaned_output = llm_output.strip()
            
            # Find JSON object in the response
            start_idx = cleaned_output.find('{')
            end_idx = cleaned_output.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                self.logger.error(f"❌ No JSON found in LLM response: {cleaned_output[:200]}...")
                raise ValueError("No JSON structure found in LLM response")
                
            json_str = cleaned_output[start_idx:end_idx]
            
            # Parse JSON
            analysis_data = json.loads(json_str)
            
            # Validate required fields
            required_fields = [
                'attack_classification', 
                'propagation_method', 
                'estimated_compromise_radius',
                'business_impact',
                'confidence_score', 
                'recommended_network_response',
                'predicted_next_targets'
            ]
            
            for field in required_fields:
                if field not in analysis_data:
                    self.logger.warning(f"⚠️ Missing field in LLM response: {field}")
                    analysis_data[field] = "UNKNOWN"
            
            self.logger.info(f"✅ Successfully parsed LLM response: {analysis_data['attack_classification']}")
            
            return LLMAnalysis(
                attack_classification=analysis_data['attack_classification'],
                propagation_method=analysis_data['propagation_method'],
                estimated_compromise_radius=analysis_data['estimated_compromise_radius'],
                business_impact=analysis_data['business_impact'],
                confidence_score=float(analysis_data['confidence_score']),
                recommended_network_response=analysis_data['recommended_network_response'],
                predicted_next_targets=analysis_data['predicted_next_targets'],
                llm_analysis_text=f"LLM_ANALYSIS: {analysis_data['attack_classification']}"
            )
            
        except json.JSONDecodeError as e:
            self.logger.error(f"❌ JSON parsing failed: {e}")
            self.logger.debug(f"Raw LLM output: {llm_output}")
            raise ValueError(f"LLM response JSON parsing failed: {e}")
        except Exception as e:
            self.logger.error(f"❌ LLM response parsing failed: {e}")
            raise

    def _load_threat_patterns(self) -> Dict[str, Any]:
        """Load known threat patterns and signatures"""
        return {
            "ransomware": {
                "indicators": ["encryption", "ransom_note", "file_extension_change", "rapid_file_modification"],
                "behavior": "destructive_file_operations",
                "propagation": ["SMB", "RDP", "network_sharing"],
                "impact": "data_loss_downtime"
            },
            "trojan": {
                "indicators": ["process_injection", "unusual_network_connections", "stealth_operation"],
                "behavior": "persistence_data_exfiltration",
                "propagation": ["email", "downloads", "social_engineering"],
                "impact": "data_theft_system_compromise"
            },
            "worm": {
                "indicators": ["self_replication", "network_scanning", "rapid_spread"],
                "behavior": "autonomous_propagation",
                "propagation": ["network_vulnerabilities", "shared_resources"],
                "impact": "network_congestion_system_overload"
            },
            "crypto_miner": {
                "indicators": ["high_cpu_usage", "mining_pools", "coinbase_connections"],
                "behavior": "resource_theft",
                "propagation": ["exploit_kits", "malicious_downloads"],
                "impact": "performance_degradation"
            }
        }