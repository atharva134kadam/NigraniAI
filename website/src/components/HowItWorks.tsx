import { motion } from 'framer-motion';
import {
  PlugZap,
  Search,
  GitBranch,
  Settings,
  Activity,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import './HowItWorks.css';

const steps = [
  {
    number: '01',
    icon: PlugZap,
    title: 'CONNECT',
    description: 'Connect available applications, APIs, databases, logs, and relevant information sources.',
  },
  {
    number: '02',
    icon: Search,
    title: 'DISCOVER',
    description: 'Identify personal-data-related information across connected sources.',
  },
  {
    number: '03',
    icon: GitBranch,
    title: 'MAP',
    description: 'Understand how data moves across services and processing purposes.',
  },
  {
    number: '04',
    icon: Settings,
    title: 'DEFINE POLICIES',
    description: 'Configure consent, purpose, retention, and privacy-related rules.',
  },
  {
    number: '05',
    icon: Activity,
    title: 'MONITOR',
    description: 'Analyse available application and database activity continuously.',
  },
  {
    number: '06',
    icon: AlertTriangle,
    title: 'DETECT',
    description: 'Identify potential policy violations and suspicious activity.',
  },
  {
    number: '07',
    icon: Search,
    title: 'INVESTIGATE',
    description: 'Review findings with evidence and AI-assisted explanations.',
  },
  {
    number: '08',
    icon: CheckCircle2,
    title: 'ACT',
    description: 'Support remediation, incident management, and compliance readiness.',
  },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="section how-it-works-section" aria-labelledby="how-it-works-heading">
      <div className="container">
        <motion.div
          className="section-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="eyebrow">Workflow</span>
          <h2 id="how-it-works-heading">From Data Visibility to Informed Action.</h2>
          <p>
            NigraniAI follows a connected privacy-monitoring workflow that moves organisations from initial data connection through to informed remediation.
          </p>
        </motion.div>

        <div className="workflow-container" role="list">
          <motion.div
            className="workflow-track"
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5 }}
            role="listitem"
          >
            {steps.map((step, index) => (
              <motion.article
                key={step.number}
                className="workflow-step"
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-50px' }}
                transition={{ duration: 0.5, delay: 0.1 + index * 0.08 }}
                role="listitem"
              >
                <div className="step-connector">
                  <span className="step-number">{step.number}</span>
                  {index < steps.length - 1 && <span className="step-line" />}
                </div>
                <div className="step-content">
                  <div className="step-icon">
                    <step.icon size={24} strokeWidth={2} />
                  </div>
                  <h3 className="step-title">{step.title}</h3>
                  <p className="step-description">{step.description}</p>
                </div>
              </motion.article>
            ))}
          </motion.div>
        </div>
      </div>
    </section>
  );
}