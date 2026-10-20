import { motion } from 'framer-motion';
import {
  Activity,
  Database,
  Bot,
  CheckCircle2,
} from 'lucide-react';
import './WhyNigraniAI.css';

const benefits = [
  {
    icon: Activity,
    title: 'Continuous Monitoring',
    description:
      'Gain visibility into personal-data-related activity across your applications, databases, and services — not just during periodic reviews, but continuously.',
  },
  {
    icon: Database,
    title: 'Better Data Visibility',
    description:
      'Understand data sources, services, and processing relationships. Map where personal data exists, which services access it, and why it is processed.',
  },
  {
    icon: Bot,
    title: 'Intelligent Investigation',
    description:
      'Make findings easier to understand through AI-assisted explanations, investigation guidance, and suggestions for corrective and preventive actions.',
  },
  {
    icon: CheckCircle2,
    title: 'Evidence-Based Readiness',
    description:
      'Support informed compliance decisions with findings, supporting evidence, and readiness scoring across key privacy and security areas.',
  },
];

export function WhyNigraniAI() {
  return (
    <section id="why-nigraniai" className="section why-section" aria-labelledby="why-heading">
      <div className="container">
        <motion.div
          className="section-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="eyebrow">Why NigraniAI</span>
          <h2 id="why-heading">Move Beyond Manual Compliance. Build Continuous Privacy Visibility.</h2>
          <p>
            NigraniAI replaces periodic, manual assessments with intelligent, continuous monitoring that helps you understand what is actually happening with personal data in your systems.
          </p>
        </motion.div>

        <div className="benefits-grid" role="list">
          {benefits.map((benefit, index) => (
            <motion.article
              key={benefit.title}
              className="benefit-card"
              role="listitem"
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-100px' }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
            >
              <div className="benefit-icon">
                <benefit.icon size={28} strokeWidth={2} />
              </div>
              <h3 className="benefit-title">{benefit.title}</h3>
              <p className="benefit-description">{benefit.description}</p>
            </motion.article>
          ))}
        </div>

        <motion.div
          className="concluding-statement"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5, delay: 0.4 }}
        >
          <p>Know your data. Understand your risks. Make informed privacy decisions.</p>
        </motion.div>
      </div>
    </section>
  );
}