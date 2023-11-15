from slither.detectors.abstract_detector import (
    AbstractDetector, DetectorClassification
)
class InheritedReentrancyDetector(AbstractDetector):
    ARGUMENT = 'inherited-reentrancy-detector'  # Update to accept 'ReentrancyGuard' as an argument
    HELP = 'Detect reentrancy vulnerabilities in contracts that inherit from ReentrancyGuard'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'https://your-wiki-link/'
    WIKI_TITLE = 'Inherited Reentrancy Detector'
    WIKI_DESCRIPTION = 'This detector identifies reentrancy vulnerabilities in contracts that inherit from ReentrancyGuard.'
    WIKI_EXPLOIT_SCENARIO = 'An attacker can exploit reentrancy vulnerabilities to drain funds or disrupt contract behavior.'
    WIKI_RECOMMENDATION = 'Follow best practices to prevent reentrancy vulnerabilities, such as using the Checks-Effects-Interactions pattern.'

    def _detect(self):
        findings = []

        for contract in self.slither.contracts:
            # Check if the contract inherits from 'ReentrancyGuard'
            if any(inherited.name == 'ReentrancyGuard' for inherited in contract.inherits):
                for function in contract.functions:
                    if self.calls_external_contracts(function):
                        info = [
                            f'Reentrancy vulnerability found in contract: {contract.name}',
                            f'In function: {function.name}',
                            'Recommendation: Ensure proper state changes are made before interacting with external contracts.'
                        ]
                        finding = self.generate_result(info)
                        findings.append(finding)

        return findings

    def calls_external_contracts(self, function):
        for callee in function.callees:
            if callee.is_contract:
                return True
        return False
