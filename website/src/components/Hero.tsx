import { motion } from 'framer-motion';
import { ArrowRight, ChevronRight, MousePointerClick } from 'lucide-react';
import { scrollToSection } from '../utils/scroll';
import { HeroIllustration } from './HeroIllustration';
import './Hero.css';

export function Hero() {
  const handleBookDemo = () => scrollToSection('contact');
  const handleExplorePlatform = () => scrollToSection('capabilities');

  return (
    <section id="hero" className="hero" aria-labelledby="hero-heading">
      <div className="hero-background">
        <div className="hero-gradient-1"></div>
        <div className="hero-gradient-2"></div>
      </div>

      <div className="container hero-container">
        <div className="hero-content">
          <motion.div
            className="hero-badge"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <span className="badge-dot"></span>
            PRIVACY INTELLIGENCE PLATFORM
          </motion.div>

          <motion.h1
            id="hero-heading"
            className="hero-title"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
          >
            See Your Data. Understand Your Risks. Strengthen Your Privacy.
          </motion.h1>

          <motion.p
            className="hero-description"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            NigraniAI brings data mapping, consent and purpose tracking, retention monitoring, breach detection and AI-assisted investigation together in one intelligent platform.
          </motion.p>

          <motion.div
            className="hero-actions"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
          >
            <button className="btn btn-primary btn-lg" onClick={handleBookDemo}>
              Book a Demo
              <ArrowRight size={18} strokeWidth={2.5} />
            </button>
            <button className="btn btn-secondary btn-lg" onClick={handleExplorePlatform}>
              Explore the Platform
              <ChevronRight size={18} strokeWidth={2.5} />
            </button>
          </motion.div>

          <motion.div
            className="hero-trust"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
          >
            <div className="trust-indicators">
              <span className="trust-item">
                <MousePointerClick size={16} strokeWidth={2} />
                <span>No credit card required</span>
              </span>
              <span className="trust-item">
                <span className="trust-dot"></span>
                <span>30-minute personalised walkthrough</span>
              </span>
              <span className="trust-item">
                <span className="trust-dot"></span>
                <span>Tailored to your industry</span>
              </span>
            </div>
          </motion.div>
        </div>

        <motion.div
          className="hero-visual"
          initial={{ opacity: 0, x: 40 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.7, delay: 0.2 }}
        >
          <HeroIllustration />
        </motion.div>
      </div>

      <motion.div
        className="hero-scroll"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2, duration: 0.5 }}
        onClick={() => scrollToSection('problem')}
      >
        <MousePointerClick size={24} strokeWidth={2} className="scroll-icon" />
        <span className="scroll-text">Scroll to explore</span>
      </motion.div>
    </section>
  );
}