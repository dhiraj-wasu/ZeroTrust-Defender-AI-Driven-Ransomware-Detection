import logging
from typing import Dict, List, Any
from datetime import datetime
from models.schemas import ThreatAlert, LLMAnalysis
from utils.helpers import calculate_risk_score

class CoordinationEngine:
    def __init__(self, agent_manager, command_dispatcher):
        self.agent_manager = agent_manager
        self.command_dispatcher = command_dispatcher
        self.logger = logging.getLogger(__name__)
        self.emergency_modes = {}  # incident_id -> emergency_data

    async def coordinate_response(self, alert: ThreatAlert, llm_analysis: LLMAnalysis, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate network-wide response based on threat analysis"""
        self.logger.info(f"Coordinating response for incident from {alert.agent_id}")
        
        # Calculate comprehensive risk assessment
        risk_assessment = await self._assess_network_risk(alert, llm_analysis, correlation_data)
        
        # Generate response plan
        response_plan = self._generate_response_plan(alert, llm_analysis, risk_assessment)
        
        # Execute coordinated response
        await self._execute_coordinated_response(alert, response_plan, risk_assessment)
        
        return {
            'risk_assessment': risk_assessment,
            'response_plan': response_plan,
            'execution_summary': await self._get_execution_summary()
        }

    async def _assess_network_risk(self, alert: ThreatAlert, llm_analysis: LLMAnalysis, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess comprehensive network risk"""
        network_topology = await self.agent_manager.get_network_topology()
        propagation_graph = correlation_data.get('propagation_graph', {})
        
        # Calculate exposure metrics
        exposed_agents = propagation_graph.get('exposed_nodes', [])
        critical_assets_at_risk = self._identify_critical_assets(alert.agent_id, exposed_agents, network_topology)
        
        # Calculate risk score
        base_risk = calculate_risk_score(
            alert.threat_level.value,
            alert.detection_confidence,
            len(exposed_agents)
        )
        
        # Adjust based on LLM confidence and business impact
        llm_confidence = llm_analysis.confidence_score
        business_impact_multiplier = self._get_business_impact_multiplier(llm_analysis.business_impact)
        
        final_risk_score = min(10.0, base_risk * llm_confidence * business_impact_multiplier)
        
        return {
            'risk_score': final_risk_score,
            'risk_level': self._get_risk_level(final_risk_score),
            'exposed_agents': exposed_agents,
            'critical_assets_at_risk': critical_assets_at_risk,
            'propagation_likelihood': self._assess_propagation_likelihood(propagation_graph),
            'business_impact': llm_analysis.business_impact,
            'containment_urgency': self._determine_containment_urgency(final_risk_score)
        }

    def _identify_critical_assets(self, source_agent: str, exposed_agents: List[str], topology: Dict[str, Any]) -> List[str]:
        """Identify critical assets at risk"""
        critical_assets = set()
        
        # Add assets from source agent
        source_agent_data = None  # Would get from database in real implementation
        if source_agent_data and 'critical_assets' in source_agent_data:
            critical_assets.update(source_agent_data['critical_assets'])
        
        # Add common critical infrastructure
        common_critical = ['domain-controller', 'file-server', 'backup-system', 'database-server']
        critical_assets.update(common_critical)
        
        return list(critical_assets)

    def _get_business_impact_multiplier(self, business_impact: str) -> float:
        """Get multiplier based on business impact assessment"""
        multipliers = {
            'HIGH': 1.5,
            'MEDIUM': 1.2,
            'LOW': 0.8
        }
        
        for level, multiplier in multipliers.items():
            if level in business_impact.upper():
                return multiplier
        return 1.0

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 8.0:
            return 'CRITICAL'
        elif risk_score >= 6.0:
            return 'HIGH'
        elif risk_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _assess_propagation_likelihood(self, propagation_graph: Dict[str, Any]) -> str:
        """Assess likelihood of further propagation"""
        propagation_paths = propagation_graph.get('propagation_paths', [])
        exposed_nodes = propagation_graph.get('exposed_nodes', [])
        
        if len(propagation_paths) >= 3:
            return 'VERY_HIGH'
        elif len(propagation_paths) >= 1:
            return 'HIGH'
        elif exposed_nodes:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _determine_containment_urgency(self, risk_score: float) -> str:
        """Determine containment urgency"""
        if risk_score >= 8.0:
            return 'IMMEDIATE'
        elif risk_score >= 6.0:
            return 'URGENT'
        elif risk_score >= 4.0:
            return 'PRIORITY'
        else:
            return 'MONITOR'

    def _generate_response_plan(self, alert: ThreatAlert, llm_analysis: LLMAnalysis, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive response plan"""
        risk_level = risk_assessment['risk_level']
        response_strategy = llm_analysis.recommended_network_response
        
        if risk_level == 'CRITICAL' or response_strategy == 'AGGRESSIVE_CONTAINMENT':
            return self._generate_aggressive_containment_plan(alert, risk_assessment)
        elif risk_level == 'HIGH' or response_strategy == 'TARGETED_CONTAINMENT':
            return self._generate_targeted_containment_plan(alert, risk_assessment)
        else:
            return self._generate_enhanced_monitoring_plan(alert, risk_assessment)

    def _generate_aggressive_containment_plan(self, alert: ThreatAlert, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate aggressive containment plan for critical threats"""
        return {
            'response_level': 'AGGRESSIVE_CONTAINMENT',
            'duration': 'emergency_1hour',
            'infected_agent_commands': [
                'maintain_full_isolation',
                'begin_forensic_collection',
                'prepare_deep_scan_recovery',
                'do_not_reconnect_network'
            ],
            'exposed_agent_commands': [
                'block_all_inbound_traffic',
                'enable_maximum_zero_trust',
                'lock_all_sensitive_directories',
                'trigger_immediate_backup',
                'enable_process_whitelisting'
            ],
            'network_wide_commands': [
                'block_p2p_communications',
                'isolate_affected_network_segments',
                'enable_enterprise_protection_mode',
                'alert_security_team_immediately'
            ],
            'communication_protocol': {
                'updates_every': '2_minutes',
                'status_reports': 'every_5_minutes',
                'escalation_points': ['CISO', 'Network_Admin', 'Security_Team']
            }
        }

    def _generate_targeted_containment_plan(self, alert: ThreatAlert, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate targeted containment plan for high threats"""
        return {
            'response_level': 'TARGETED_CONTAINMENT',
            'duration': 'enhanced_4hours',
            'infected_agent_commands': [
                'restrict_network_access',
                'enable_enhanced_monitoring',
                'backup_critical_files',
                'scan_for_persistence'
            ],
            'exposed_agent_commands': [
                'block_suspicious_protocols',
                'enable_enhanced_protection',
                'monitor_lateral_movement',
                'increase_logging_verbosity'
            ],
            'network_wide_commands': [
                'monitor_cross_segment_traffic',
                'alert_related_departments',
                'enable_selective_isolation'
            ],
            'communication_protocol': {
                'updates_every': '5_minutes',
                'status_reports': 'every_15_minutes',
                'escalation_points': ['Security_Team', 'Department_Head']
            }
        }

    def _generate_enhanced_monitoring_plan(self, alert: ThreatAlert, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate enhanced monitoring plan for medium/low threats"""
        return {
            'response_level': 'ENHANCED_MONITORING',
            'duration': 'monitoring_24hours',
            'infected_agent_commands': [
                'increase_security_logging',
                'monitor_process_activity',
                'report_suspicious_behavior',
                'maintain_normal_operations'
            ],
            'exposed_agent_commands': [
                'enable_preventive_protection',
                'monitor_for_similar_patterns',
                'ready_isolation_protocols'
            ],
            'network_wide_commands': [
                'continue_normal_operations',
                'monitor_network_health'
            ],
            'communication_protocol': {
                'updates_every': '15_minutes',
                'status_reports': 'every_hour',
                'escalation_points': ['Security_Team']
            }
        }

    async def _execute_coordinated_response(self, alert: ThreatAlert, response_plan: Dict[str, Any], risk_assessment: Dict[str, Any]):
        """Execute the coordinated network response"""
        risk_level = risk_assessment['risk_level']
        
        if risk_level in ['CRITICAL', 'HIGH']:
            await self._activate_emergency_protocol(alert, response_plan, risk_assessment)
        
        # Dispatch commands to infected agent
        infected_commands = response_plan.get('infected_agent_commands', [])
        if infected_commands:
            await self.command_dispatcher.dispatch_agent_command(
                alert.agent_id, 
                infected_commands,
                getattr(alert, 'incident_id', 'unknown')
            )
        
        # Dispatch commands to exposed agents
        exposed_agents = risk_assessment.get('exposed_agents', [])
        exposed_commands = response_plan.get('exposed_agent_commands', [])
        for agent_id in exposed_agents:
            await self.command_dispatcher.dispatch_agent_command(
                agent_id,
                exposed_commands,
                getattr(alert, 'incident_id', 'unknown')
            )
        
        # Execute network-wide commands if needed
        network_commands = response_plan.get('network_wide_commands', [])
        if network_commands and risk_level in ['CRITICAL', 'HIGH']:
            await self._execute_network_wide_commands(alert, network_commands)

    async def _activate_emergency_protocol(self, alert: ThreatAlert, response_plan: Dict[str, Any], risk_assessment: Dict[str, Any]):
        """Activate emergency defense protocol"""
        incident_id = getattr(alert, 'incident_id', 'unknown')
        emergency_data = {
            'incident_id': incident_id,
            'threat_level': alert.threat_level.value,
            'affected_agent': alert.agent_id,
            'response_level': response_plan['response_level'],
            'activated_at': datetime.now().isoformat(),
            'duration': response_plan['duration'],
            'required_actions': response_plan.get('network_wide_commands', [])
        }
        
        self.emergency_modes[incident_id] = emergency_data
        
        # Broadcast emergency notification
        await self.command_dispatcher.broadcast_network_incident(emergency_data)
        self.logger.warning(f"EMERGENCY PROTOCOL ACTIVATED for incident {incident_id}")

    async def _execute_network_wide_commands(self, alert: ThreatAlert, commands: List[str]):
        """Execute network-wide commands"""
        # This would interface with network infrastructure
        # For now, log the commands that would be executed
        self.logger.info(f"Network-wide commands for {alert.agent_id}: {commands}")

    async def _get_execution_summary(self) -> Dict[str, Any]:
        """Get summary of response execution"""
        return {
            'emergency_modes_active': len(self.emergency_modes),
            'last_coordination': datetime.now().isoformat(),
            'active_incidents': list(self.emergency_modes.keys())
        }