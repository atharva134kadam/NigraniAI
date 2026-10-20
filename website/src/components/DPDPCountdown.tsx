import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import './DPDPCountdown.css';

const TARGET_DATE = new Date('2027-05-13T00:00:00+05:30');

export function DPDPCountdown() {
  const [now, setNow] = useState<Date>(new Date());
  const [countdown, setCountdown] = useState<{ days: number; hours: number; minutes: number; seconds: number; isExpired: boolean }>({ days: 0, hours: 0, minutes: 0, seconds: 0, isExpired: false });

  const calculateCountdown = () => {
    const diff = TARGET_DATE.getTime() - now.getTime();
    if (diff <= 0) {
      return { days: 0, hours: 0, minutes: 0, seconds: 0, isExpired: true };
    }
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);
    return { days, hours, minutes, seconds, isExpired: false };
  };

  useEffect(() => {
    setCountdown(calculateCountdown());
    const interval = setInterval(() => {
      setNow(new Date());
      setCountdown(calculateCountdown());
    }, 1000);
    return () => clearInterval(interval);
  }, [now]);

  return (
    <section id="compliance-countdown" className="section countdown-section" aria-labelledby="countdown-heading">
      <div className="container">
        {/* Introduction */}
        <motion.div
          className="countdown-intro"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="intro-label">THE COUNTDOWN</span>
          <h2 id="countdown-heading" className="intro-headline">
            The compliance window is already closing
          </h2>
          <p className="intro-description">
            The law is not theoretical anymore. With enforcement expected around May 2027, the runway to operationalise consent and rights is measured in months, not years. And the work runs in sequence: map the data, serve fresh notices, then stand up consent and rights.
          </p>
        </motion.div>

        {/* Main Countdown Panel */}
        <motion.div
          className="countdown-panel"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.6, delay: 0.1 }}
        >
          {/* Panel Header with Live Indicator */}
          <div className="panel-header">
            <div className="header-left">
              <span className="panel-live-badge">ENFORCEMENT CLOCK · LIVE</span>
            </div>
            <div className="header-center">
              <div className="countdown-grid" role="timer" aria-live="polite" aria-label="Countdown to enforcement">
                <div className="countdown-box">
                  <span className="countdown-value" aria-label={`${countdown.days} days`}>
                    {String(countdown.days).padStart(2, '0')}
                  </span>
                  <span className="countdown-label">DAYS</span>
                </div>
                <div className="countdown-box">
                  <span className="countdown-value" aria-label={`${countdown.hours} hours`}>
                    {String(countdown.hours).padStart(2, '0')}
                  </span>
                  <span className="countdown-label">HRS</span>
                </div>
                <div className="countdown-box">
                  <span className="countdown-value" aria-label={`${countdown.minutes} minutes`}>
                    {String(countdown.minutes).padStart(2, '0')}
                  </span>
                  <span className="countdown-label">MIN</span>
                </div>
                <div className="countdown-box">
                  <span className="countdown-value" aria-label={`${countdown.seconds} seconds`}>
                    {String(countdown.seconds).padStart(2, '0')}
                  </span>
                  <span className="countdown-label">SEC</span>
                </div>
              </div>
            </div>
            <div className="header-right">
              <div className="panel-milestone-label">
                <span>Enforcement · </span>
                <span className="milestone-date">May 13, 2027</span>
              </div>
            </div>
          </div>

          {countdown.isExpired && (
            <div className="countdown-expired">
              Enforcement milestone has been reached.
            </div>
          )}

          {/* Divider */}
          <div className="panel-divider" />

          {/* Horizontal Timeline */}
          <div className="timeline-section">
            <div className="timeline-container">
              <div className="timeline-track">
                {/* Progress line */}
                <div className="timeline-progress">
                  <div className="timeline-progress-fill" style={{ width: '66.66%' }} />
                </div>
                {/* Timeline markers */}
                <div className="timeline-marker completed" style={{ left: '0%' }}>
                  <div className="marker-circle">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  </div>
                  <div className="marker-label">
                    <span className="marker-date">August 11, 2023</span>
                    <span className="marker-status">DONE</span>
                  </div>
                </div>
                <div className="timeline-marker completed" style={{ left: '50%' }}>
                  <div className="marker-circle">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  </div>
                  <div className="marker-label">
                    <span className="marker-date">November 13, 2025</span>
                    <span className="marker-status">DONE</span>
                  </div>
                </div>
                <div className="timeline-marker deadline" style={{ left: '100%' }}>
                  <div className="marker-circle deadline">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <polyline points="12 6 12 12 16 14" />
                    </svg>
                  </div>
                  <div className="marker-label">
                    <span className="marker-date">May 13, 2027</span>
                    <span className="marker-status">DEADLINE</span>
                  </div>
                </div>
                {/* YOU ARE HERE indicator */}
                <div className="you-are-here" style={{ left: '66.66%' }}>
                  <span>YOU ARE HERE</span>
                </div>
              </div>
            </div>
          </div>

          {/* Three Milestone Cards */}
          <div className="milestone-cards">
            <article className="milestone-card done strikethrough">
              <div className="card-status">DONE</div>
              <div className="card-date strikethrough">August 11, 2023</div>
              <h3 className="card-title strikethrough">DPDP Act Enacted</h3>
              <p className="card-description strikethrough">DPDP Act enacted by Parliament.</p>
            </article>
            <article className="milestone-card done strikethrough">
              <div className="card-status">DONE</div>
              <div className="card-date strikethrough">November 13, 2025</div>
              <h3 className="card-title strikethrough">DPDP Rules Notified</h3>
              <p className="card-description strikethrough">DPDP Rules notified · transition begins. Months, not years, to build consent, rights & breach workflows.</p>
            </article>
            <article className="milestone-card deadline">
              <div className="card-status">DEADLINE</div>
              <div className="card-date">May 13, 2027</div>
              <h3 className="card-title">Enforcement</h3>
              <p className="card-description">Enforcement · penalties active, audits & scrutiny begin.</p>
            </article>
          </div>
        </motion.div>
      </div>
    </section>
  );
}