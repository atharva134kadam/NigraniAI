import { motion } from 'framer-motion';
import { scrollToSection } from '../utils/scroll';
import './Footer.css';

const footerLinks = {
  platform: [
    { label: 'Platform', href: '#platform' },
    { label: 'Capabilities', href: '#capabilities' },
    { label: 'How It Works', href: '#how-it-works' },
    { label: 'Understand DPDPA', href: '#dpdpa' },
  ],
  company: [
    { label: 'About', href: '#about' },
    { label: 'Contact', href: '#contact' },
    { label: 'Book a Demo', href: '#contact' },
  ],
  legal: [
    { label: 'Privacy Policy', href: '#privacy-policy' },
    { label: 'Terms & Conditions', href: '#terms-conditions' },
    { label: 'Cookie Preferences', href: '#cookie-preferences' },
  ],
};

export function Footer() {
  const handleLinkClick = (e: React.MouseEvent, href: string) => {
    if (href.startsWith('#')) {
      e.preventDefault();
      if (href === '#cookie-preferences') {
        // Dispatch custom event to reopen cookie settings
        window.dispatchEvent(new CustomEvent('reopen-cookie-settings'));
      } else {
        scrollToSection(href.slice(1));
      }
    }
  };

  return (
    <footer className="footer" role="contentinfo">
      <div className="container">
        <motion.div
          className="footer-grid"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <div className="footer-brand">
            <img src="/images/nigraniai-logo.jpeg" alt="" className="footer-logo" />
            <p className="footer-description">
              NigraniAI is an intelligent privacy and compliance monitoring platform that gives organisations visibility into personal-data processing and helps them identify, investigate, and manage privacy risks.
            </p>
            <p className="footer-tagline">Intelligent Privacy. Continuous Monitoring. Stronger Compliance Readiness.</p>
          </div>

          <nav className="footer-nav" aria-label="Platform links">
            <h4>Platform</h4>
            <ul>
              {footerLinks.platform.map(link => (
                <li key={link.href}>
                  <a href={link.href} onClick={e => handleLinkClick(e, link.href)}>{link.label}</a>
                </li>
              ))}
            </ul>
          </nav>

          <nav className="footer-nav" aria-label="Company links">
            <h4>Company</h4>
            <ul>
              {footerLinks.company.map(link => (
                <li key={link.href}>
                  <a href={link.href} onClick={e => handleLinkClick(e, link.href)}>{link.label}</a>
                </li>
              ))}
            </ul>
          </nav>

          <nav className="footer-nav" aria-label="Legal links">
            <h4>Legal</h4>
            <ul>
              {footerLinks.legal.map(link => (
                <li key={link.href}>
                  <a href={link.href} onClick={e => handleLinkClick(e, link.href)}>{link.label}</a>
                </li>
              ))}
            </ul>
          </nav>
        </motion.div>

        <motion.div
          className="footer-bottom"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          <div className="footer-divider" />
          <p className="copyright">
            &copy; {new Date().getFullYear()} NigraniAI. All rights reserved.
          </p>
        </motion.div>

        <div id="privacy-policy" className="legal-page" hidden>
          <h2>Privacy Policy</h2>
          <p><strong>Last updated:</strong> {new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
          <p>This Privacy Policy explains how NigraniAI ("we", "our", "us") collects, uses, and protects your information when you visit our website.</p>
          <h3>1. Information We Collect</h3>
          <p>We collect information you provide directly to us, such as when you fill out a demo request form. This includes your name, business email, phone number, organisation details, and preferences.</p>
          <h3>2. How We Use Your Information</h3>
          <p>We use your information to respond to your demo request, schedule a personalised demonstration, and communicate with you about our platform.</p>
          <h3>3. Data Storage</h3>
          <p>Demo request data is stored securely in our Supabase database with Row Level Security enabled. We do not sell or share your personal information with third parties.</p>
          <h3>4. Cookies</h3>
          <p>We use cookies as described in our cookie consent banner. You can manage your preferences at any time.</p>
          <h3>5. Your Rights</h3>
          <p>You may request access to, correction of, or deletion of your personal data by contacting us at demo@nigraniai.com.</p>
          <h3>6. Changes to This Policy</h3>
          <p>We may update this policy from time to time. Changes will be posted on this page with an updated date.</p>
        </div>

        <div id="terms-conditions" className="legal-page" hidden>
          <h2>Terms & Conditions</h2>
          <p><strong>Last updated:</strong> {new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
          <p>By accessing and using the NigraniAI website, you agree to these Terms & Conditions.</p>
          <h3>1. Use of Website</h3>
          <p>This website provides information about the NigraniAI platform. Content is for general informational purposes only and does not constitute legal advice.</p>
          <h3>2. Demo Requests</h3>
          <p>Submitting a demo request does not create a binding agreement or confirmed booking. Our team will contact you to discuss and confirm meeting details.</p>
          <h3>3. Intellectual Property</h3>
          <p>All content, logos, and trademarks on this website are the property of NigraniAI or its licensors.</p>
          <h3>4. Limitation of Liability</h3>
          <p>NigraniAI is not liable for any damages arising from the use of this website or reliance on its content. The platform capabilities described are based on current functionality and may evolve.</p>
          <h3>5. Governing Law</h3>
          <p>These terms are governed by the laws of India.</p>
        </div>
      </div>
    </footer>
  );
}