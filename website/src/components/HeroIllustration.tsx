import { motion } from 'framer-motion';
import {
  Database,
  Shield,
  Activity,
  Cpu,
  Eye,
  BarChart2,
  Sparkles,
} from 'lucide-react';
import './HeroIllustration.css';

const stages = [
  {
    id: 'discover',
    label: 'DISCOVER',
    subtitle: 'Personal Data',
    icon: Database,
    color: 'var(--color-primary)',
    position: { top: '10%', left: '8%' },
    delay: 0.2,
  },
  {
    id: 'evaluate',
    label: 'EVALUATE',
    subtitle: 'Privacy Policies',
    icon: Shield,
    color: 'var(--color-secondary)',
    position: { top: '10%', right: '8%' },
    delay: 0.4,
  },
  {
    id: 'monitor',
    label: 'MONITOR',
    subtitle: 'Data Activity',
    icon: Activity,
    color: 'var(--color-accent)',
    position: { bottom: '10%', left: '50%', transform: 'translateX(-50%)' },
    delay: 0.6,
  },
];

const centralSteps = [
  { label: 'Connect', icon: Cpu, delay: 0.8 },
  { label: 'Analyse', icon: Eye, delay: 1.0 },
  { label: 'Investigate', icon: Sparkles, delay: 1.2 },
];

const outcomes = [
  { label: 'Visibility', icon: Eye },
  { label: 'Insights', icon: BarChart2 },
  { label: 'Risk Awareness', icon: Shield },
];

export function HeroIllustration() {
  return (
    <div className="hero-illustration" aria-label="Conceptual illustration of NigraniAI's privacy intelligence workflow">
      {/* Background glow */}
      <div className="illustration-bg-glow" />

      {/* Connecting lines from stages to center */}
      <svg className="flow-lines" viewBox="0 0 400 400" preserveAspectRatio="none">
        <defs>
          <linearGradient id="flowGradient1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="var(--color-primary)" stopOpacity="0.4" />
            <stop offset="50%" stopColor="var(--color-accent)" stopOpacity="0.3" />
            <stop offset="100%" stopColor="var(--color-secondary)" stopOpacity="0.4" />
          </linearGradient>
          <linearGradient id="flowGradient2" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="var(--color-secondary)" stopOpacity="0.4" />
            <stop offset="50%" stopColor="var(--color-accent)" stopOpacity="0.3" />
            <stop offset="100%" stopColor="var(--color-primary)" stopOpacity="0.4" />
          </linearGradient>
          <linearGradient id="flowGradient3" x1="50%" y1="100%" x2="50%" y2="0%">
            <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0.4" />
            <stop offset="50%" stopColor="var(--color-primary)" stopOpacity="0.3" />
            <stop offset="100%" stopColor="var(--color-secondary)" stopOpacity="0.4" />
          </linearGradient>
        </defs>
        {/* Line from Discover (top-left) to center */}
        <path
          className="flow-line"
          d="M 60 60 Q 150 150 200 200"
          stroke="url(#flowGradient1)"
          strokeWidth="2"
          fill="none"
          strokeDasharray="8,4"
        />
        {/* Line from Evaluate (top-right) to center */}
        <path
          className="flow-line"
          d="M 340 60 Q 250 150 200 200"
          stroke="url(#flowGradient2)"
          strokeWidth="2"
          fill="none"
          strokeDasharray="8,4"
        />
        {/* Line from Monitor (bottom-center) to center */}
        <path
          className="flow-line"
          d="M 200 340 Q 200 270 200 200"
          stroke="url(#flowGradient3)"
          strokeWidth="2"
          fill="none"
          strokeDasharray="8,4"
        />
        {/* Animated particles on lines */}
        <g className="particles">
          <circle className="particle" r="3" fill="var(--color-accent)">
            <animateMotion
              dur="3s"
              repeatCount="indefinite"
              path="M 60 60 Q 150 150 200 200"
              rotate="auto"
            />
          </circle>
          <circle className="particle" r="3" fill="var(--color-accent)">
            <animateMotion
              dur="3s"
              repeatCount="indefinite"
              path="M 340 60 Q 250 150 200 200"
              rotate="auto"
            />
          </circle>
          <circle className="particle" r="3" fill="var(--color-accent)">
            <animateMotion
              dur="3s"
              repeatCount="indefinite"
              path="M 200 340 Q 200 270 200 200"
              rotate="auto"
            />
          </circle>
        </g>
      </svg>

      {/* Stage Nodes */}
      {stages.map((stage) => (
        <motion.div
          key={stage.id}
          className="stage-node"
          style={{
            ...stage.position,
            '--stage-color': stage.color,
          } as unknown as React.CSSProperties}
          initial={{ opacity: 0, scale: 0.8, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.6, delay: stage.delay, type: 'spring', stiffness: 100 }}
        >
          <div className="stage-ring" />
          <div className="stage-circle">
            <stage.icon size={22} strokeWidth={2.5} className="stage-icon" />
          </div>
          <div className="stage-labels">
            <span className="stage-main">{stage.label}</span>
            <span className="stage-sub">{stage.subtitle}</span>
          </div>
          <motion.div
            className="stage-pulse"
            animate={{ scale: [1, 1.3, 1], opacity: [0.4, 0, 0.4] }}
            transition={{ duration: 2, repeat: Infinity, delay: stage.delay * 2 }}
          />
        </motion.div>
      ))}

      {/* Central NigraniAI Intelligence Element */}
      <motion.div
        className="central-element"
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.8, delay: 0.7, type: 'spring', stiffness: 80 }}
      >
        <div className="central-glow" />
        <div className="central-ring" />
        <div className="central-core">
          <Cpu size={28} strokeWidth={2} className="central-icon" />
        </div>
        <span className="central-label">NigraniAI Intelligence</span>

        {/* Central Steps */}
        <div className="central-steps">
          {centralSteps.map((step) => (
            <motion.div
              key={step.label}
              className="central-step"
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.4, delay: step.delay }}
            >
              <div className="step-dot" />
              <span className="step-label">{step.label}</span>
              <step.icon size={14} strokeWidth={2} className="step-icon" />
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Outcome Labels at Bottom */}
      <motion.div
        className="outcomes-row"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 1.4 }}
      >
        {outcomes.map((outcome) => (
          <motion.div
            key={outcome.label}
            className="outcome-item"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 1.5 }}
          >
            <outcome.icon size={18} strokeWidth={2} className="outcome-icon" />
            <span className="outcome-label">{outcome.label}</span>
          </motion.div>
        ))}
      </motion.div>

      {/* Caption */}
      <motion.p
        className="illustration-caption"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5, delay: 1.8 }}
      >
        Conceptual illustration of NigraniAI&apos;s privacy intelligence workflow
      </motion.p>
    </div>
  );
}