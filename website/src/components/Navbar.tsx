import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X } from 'lucide-react';
import { scrollToSection } from '../utils/scroll';
import './Navbar.css';

const navLinks = [
  { id: 'platform', label: 'Platform' },
  { id: 'capabilities', label: 'Capabilities' },
  { id: 'how-it-works', label: 'How It Works' },
  { id: 'dpdpa', label: 'Understand DPDPA' },
  { id: 'about', label: 'About' },
  { id: 'contact', label: 'Contact' },
];

export function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('platform');

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    const sections = navLinks.map(link => document.getElementById(link.id));
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      { rootMargin: '-30% 0px -60% 0px', threshold: 0.1 }
    );
    sections.forEach(section => section && observer.observe(section));
    return () => observer.disconnect();
  }, []);

  const handleNavClick = (id: string) => {
    scrollToSection(id);
    setIsMobileMenuOpen(false);
  };

  const handleDemoClick = () => {
    scrollToSection('contact');
    setIsMobileMenuOpen(false);
  };

  return (
    <>
      <a href="#main-content" className="skip-link">Skip to main content</a>
      <nav
        className={`navbar ${isScrolled ? 'scrolled' : ''}`}
        role="navigation"
        aria-label="Main navigation"
      >
        <div className="navbar-container container">
          <a href="#" className="navbar-logo" aria-label="NigraniAI Home" onClick={(e) => { e.preventDefault(); scrollToSection('hero'); }}>
            <img src="/images/nigraniai-logo.jpeg" alt="" className="logo-image" />
          </a>

          <div className={`navbar-menu ${isMobileMenuOpen ? 'open' : ''}`} role="menubar">
            <ul className="navbar-nav" role="menubar">
              {navLinks.map(link => (
                <li key={link.id} role="none">
                  <button
                    role="menuitem"
                    className={`nav-link ${activeSection === link.id ? 'active' : ''}`}
                    onClick={() => handleNavClick(link.id)}
                    aria-current={activeSection === link.id ? 'page' : undefined}
                  >
                    {link.label}
                  </button>
                </li>
              ))}
            </ul>

            <div className="navbar-actions">
              <button className="btn btn-primary" onClick={handleDemoClick}>
                Book a Demo
              </button>
            </div>
          </div>

          <button
            className="navbar-toggle"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            aria-expanded={isMobileMenuOpen}
            aria-controls="navbar-menu"
            aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
          >
            <AnimatePresence mode="wait">
              {isMobileMenuOpen ? (
                <motion.div
                  initial={{ rotate: -90 }}
                  animate={{ rotate: 0 }}
                  exit={{ rotate: 90 }}
                  transition={{ duration: 0.2 }}
                >
                  <X size={24} strokeWidth={2.5} />
                </motion.div>
              ) : (
                <motion.div
                  initial={{ rotate: 90 }}
                  animate={{ rotate: 0 }}
                  exit={{ rotate: -90 }}
                  transition={{ duration: 0.2 }}
                >
                  <Menu size={24} strokeWidth={2.5} />
                </motion.div>
              )}
            </AnimatePresence>
          </button>
        </div>
      </nav>
    </>
  );
}