import { motion } from 'framer-motion';
import {
  EyeOff,
  Database,
  ShieldAlert,
  Clock,
  AlertTriangle,
  FileSearch,
} from 'lucide-react';
import './ProblemSection.css';

const problems = [
  {
    icon: EyeOff,
    title: 'Limited Visibility',
    description: 'Organisations struggle to see what personal data is being collected, where it resides, and which services access it across their technical estate.',
  },
  {
    icon: Database,
    title: 'Data Location Uncertainty',
    description: 'Difficulty tracking where personal data is stored and accessed across applications, databases, APIs, and third-party services.',
  },
  {
    icon: ShieldAlert,
    title: 'Consent & Purpose Mismatches',
    description: 'Processing activities may not align with available consent records or declared purposes, creating compliance gaps that go undetected.',
  },
  {
    icon: Clock,
    title: 'Retention & Erasure Gaps',
    description: 'Records often remain stored beyond applicable retention deadlines, and erasure obligations are difficult to track and fulfil.',
  },
  {
    icon: AlertTriangle,
    title: 'Suspicious Activity Blind Spots',
    description: 'Unusual data access patterns, bulk exports, or anomalous behaviour may indicate potential breaches but remain unnoticed.',
  },
  {
    icon: FileSearch,
    title: 'Manual & Scattered Reviews',
    description: 'Compliance depends on periodic manual assessments, questionnaires, and spreadsheets instead of continuous, evidence-based monitoring.',
  },
];

export function ProblemSection() {
  return (
    <section id="problem" className="section problem-section" aria-labelledby="problem-heading">
      <div className="container">
        <motion.div
          className="section-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="eyebrow">The Challenge</span>
          <h2 id="problem-heading">Personal Data Is Everywhere. Is Your Organisation Really Monitoring It?</h2>
          <p>
            Traditional compliance approaches depend on manual assessments and periodic reviews.
            They may not reveal what is actually happening inside your applications and databases.
          </p>
        </motion.div>

        <div className="problems-grid" role="list">
          {problems.map((problem, index) => (
            <motion.article
              key={problem.title}
              className="problem-card"
              role="listitem"
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-100px' }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
            >
              <div className="problem-icon">
                <problem.icon size={24} strokeWidth={2} />
              </div>
              <h3 className="problem-title">{problem.title}</h3>
              <p className="problem-description">{problem.description}</p>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}