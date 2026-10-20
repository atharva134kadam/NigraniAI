import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Database,
  Shield,
  Clock,
  AlertTriangle,
  Bot,
  CheckCircle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import './Capabilities.css';

const capabilities = [
  {
    icon: Database,
    title: 'Data Mapping',
    description:
      'Understand where personal data exists, which services access it, and how it moves across the organisation.',
    details: [
      'Service inventory and personal-data field mapping',
      'Processing purpose and data recipient tracking',
      'Records of processing activities (ROPA) generation',
      'Cross-service data flow visualisation',
      'Data inventory comparison with consent records',
    ],
  },
  {
    icon: Shield,
    title: 'Consent & Purpose',
    description:
      'Monitor processing activities against available consent records, privacy notices, and declared purposes.',
    details: [
      'Eight configurable policy rules (R1–R8)',
      'Consent coverage by service and customer',
      'Customer-wise consent timelines',
      'Marketing opt-in validation',
      'Outdated notice detection',
      'Erasure request enforcement checking',
      'Policy versioning with change preview',
    ],
  },
  {
    icon: Clock,
    title: 'Retention Monitoring',
    description:
      'Identify records approaching or exceeding configured retention deadlines and manage erasure-related worklists.',
    details: [
      'Retention overview with past-deadline & upcoming records',
      'Erasure requests and legal holds tracking',
      'Inactive account identification',
      'Configurable retention schedules with preview',
      'Exportable worklists for service owners',
      'Read-only monitoring — no automatic deletion',
    ],
  },
  {
    icon: AlertTriangle,
    title: 'Breach Detection',
    description:
      'Identify suspicious activity through configurable detection rules and machine-learning-based anomaly detection.',
    details: [
      'Seven editable rule-based detectors with conditions & thresholds',
      'Isolation Forest ML anomaly model for unusual patterns',
      'Signal review workflow: Review → Investigate → Dismiss/Escalate',
      'Incident lifecycle: Suspected → Confirmed → Contained → Closed',
      'Configurable response clocks (CERT-In, Board, Customer)',
      'Notification drafts prepared — not auto-sent',
    ],
  },
  {
    icon: Bot,
    title: 'AI Assistant',
    description:
      'Get AI-assisted explanations, investigation guidance, and suggestions for corrective and preventive actions.',
    details: [
      'Explain findings in simple language',
      'Investigate root causes with evidence context',
      'Suggest corrective actions for compliance issues',
      'Recommend preventive measures',
      'Interpret retention & consent requirements',
      'Structured responses: Answer → Why it matters → What to do → How to prevent',
      'Human review required — AI can make mistakes',
    ],
  },
  {
    icon: CheckCircle,
    title: 'DPDP Readiness Score',
    description:
      'Understand readiness across important privacy and security areas with supporting findings and evidence.',
    details: [
      'Eight assessment areas scored 0–100 (A–E grades)',
      'Areas: Security Monitoring, Breach Readiness, Consent & Purpose, Retention, Access Control, Logging Coverage, Public Exposure, Records & Evidence',
      'Public exposure test via connected database public key',
      'Evidence ledger with hash-chained tamper detection',
      'Audit packs and integrity verification',
      'Supporting findings with regulatory references',
    ],
  },
];

export function Capabilities() {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  const toggleExpand = (index: number) => {
    setExpandedIndex(expandedIndex === index ? null : index);
  };

  return (
    <section id="capabilities" className="section capabilities-section" aria-labelledby="capabilities-heading">
      <div className="container">
        <motion.div
          className="section-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="eyebrow">Platform Capabilities</span>
          <h2 id="capabilities-heading">One Platform. Multiple Layers of Privacy Intelligence.</h2>
          <p>
            NigraniAI brings together data visibility, consent validation, retention monitoring, breach detection, AI assistance, and readiness scoring in a single platform.
          </p>
        </motion.div>

        <div className="capabilities-grid" role="list">
          {capabilities.map((capability, index) => (
            <motion.article
              key={capability.title}
              className="capability-card"
              role="listitem"
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-100px' }}
              transition={{ duration: 0.5, delay: index * 0.08 }}
            >
              <div className="capability-header">
                <div className="capability-icon">
                  <capability.icon size={24} strokeWidth={2} />
                </div>
                <div className="capability-title-row">
                  <h3 className="capability-title">{capability.title}</h3>
                  <button
                    className="expand-toggle"
                    onClick={() => toggleExpand(index)}
                    aria-expanded={expandedIndex === index}
                    aria-controls={`capability-details-${index}`}
                  >
                    {expandedIndex === index ? (
                      <ChevronUp size={20} strokeWidth={2.5} />
                    ) : (
                      <ChevronDown size={20} strokeWidth={2.5} />
                    )}
                  </button>
                </div>
              </div>
              <p className="capability-description">{capability.description}</p>

              <AnimatePresence>
                {expandedIndex === index && (
                  <motion.div
                    id={`capability-details-${index}`}
                    className="capability-details"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <ul className="capability-detail-list">
                      {capability.details.map((detail, i) => (
                        <li key={i}>
                          <span className="detail-bullet" />
                          {detail}
                        </li>
                      ))}
                    </ul>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}