import { motion } from 'framer-motion';
import { Target, Eye, Users, Shield } from 'lucide-react';
import './About.css';

export function About() {
  return (
    <section id="about" className="section about-section" aria-labelledby="about-heading">
      <div className="container">
        <motion.div
          className="section-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="eyebrow">About NigraniAI</span>
          <h2 id="about-heading">Building a More Transparent and Accountable Data Environment.</h2>
        </motion.div>

        <div className="about-content">
          <motion.div
            className="about-main"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="about-card">
              <div className="about-card-icon">
                <Target size={24} strokeWidth={2} />
              </div>
              <h3>Mission</h3>
              <p>
                To help organisations gain continuous visibility into personal-data processing and make more informed privacy and compliance decisions.
              </p>
            </div>

            <div className="about-card">
              <div className="about-card-icon">
                <Eye size={24} strokeWidth={2} />
              </div>
              <h3>Vision</h3>
              <p>
                To support a transparent, accountable, and privacy-conscious digital ecosystem.
              </p>
            </div>
          </motion.div>

          <motion.div
            className="about-principles"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <h3>Our Principles</h3>
            <div className="principles-grid">
              <div className="principle-item">
                <div className="principle-icon">
                  <Shield size={20} strokeWidth={2} />
                </div>
                <div>
                  <h4>Accuracy Over Hype</h4>
                  <p>We communicate actual capabilities without exaggeration. No unimplemented features advertised as operational.</p>
                </div>
              </div>
              <div className="principle-item">
                <div className="principle-icon">
                  <Users size={20} strokeWidth={2} />
                </div>
                <div>
                  <h4>Human-Centred</h4>
                  <p>AI assists human investigation; it does not replace legal or compliance professionals. Review is always required.</p>
                </div>
              </div>
              <div className="principle-item">
                <div className="principle-icon">
                  <Target size={20} strokeWidth={2} />
                </div>
                <div>
                  <h4>Evidence-Based</h4>
                  <p>Findings are grounded in actual system activity and available evidence, not assumptions or checklists.</p>
                </div>
              </div>
              <div className="principle-item">
                <div className="principle-icon">
                  <Eye size={20} strokeWidth={2} />
                </div>
                <div>
                  <h4>Transparency</h4>
                  <p>Clear about what we monitor, how we detect, and what our limitations are. No black-box claims.</p>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}