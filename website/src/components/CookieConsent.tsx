import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Cookie, X, Settings, Shield, Check, BarChart2, Megaphone } from 'lucide-react';
import './CookieConsent.css';

interface CookiePreferences {
  necessary: boolean;
  analytics: boolean;
  marketing: boolean;
  timestamp: number;
  version: string;
}

const CURRENT_VERSION = '1.0';
const STORAGE_KEY = 'nigraniai-cookie-consent';

const defaultPreferences: CookiePreferences = {
  necessary: true,
  analytics: false,
  marketing: false,
  timestamp: 0,
  version: CURRENT_VERSION,
};

export function CookieConsent() {
  const [showBanner, setShowBanner] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [preferences, setPreferences] = useState<CookiePreferences>(defaultPreferences);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        if (parsed.version === CURRENT_VERSION) {
          setPreferences(parsed);
          return;
        }
      } catch {
        // Invalid stored data
      }
    }
    // No valid consent stored, show banner after a short delay
    const timer = setTimeout(() => setShowBanner(true), 1000);
    return () => clearTimeout(timer);
  }, []);

  // Listen for reopen event from footer
  useEffect(() => {
    const handleReopen = () => {
      setShowSettings(true);
      setShowBanner(false);
    };
    window.addEventListener('reopen-cookie-settings', handleReopen);
    return () => window.removeEventListener('reopen-cookie-settings', handleReopen);
  }, []);

  const savePreferences = useCallback((newPrefs: CookiePreferences) => {
    const prefsToSave = {
      ...newPrefs,
      timestamp: Date.now(),
      version: CURRENT_VERSION,
    };
    setPreferences(prefsToSave);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefsToSave));
    setShowBanner(false);
    setShowSettings(false);
  }, []);

  const handleAcceptAll = () => {
    savePreferences({ necessary: true, analytics: true, marketing: true, timestamp: 0, version: CURRENT_VERSION });
  };

  const handleRejectOptional = () => {
    savePreferences({ necessary: true, analytics: false, marketing: false, timestamp: 0, version: CURRENT_VERSION });
  };

  const handleCustomizeSave = () => {
    savePreferences({ ...preferences, necessary: true, timestamp: 0, version: CURRENT_VERSION });
  };

  const handleReopenSettings = () => {
    setShowSettings(true);
    setShowBanner(false);
  };

  if (!showBanner && !showSettings) {
    return (
      <>
        <button
          className="cookie-reopen"
          onClick={handleReopenSettings}
          aria-label="Cookie preferences"
          title="Cookie preferences"
        >
          <Cookie size={20} strokeWidth={2} />
          <span>Cookie Preferences</span>
        </button>
      </>
    );
  }

  return (
    <AnimatePresence>
      {showBanner && (
        <motion.div
          className="cookie-banner"
          initial={{ opacity: 0, y: 100 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 100 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          role="dialog"
          aria-label="Cookie consent"
          aria-describedby="cookie-description"
        >
          <div className="cookie-content">
            <div className="cookie-main">
              <div className="cookie-icon">
                <Cookie size={24} strokeWidth={2} />
              </div>
              <div className="cookie-text">
                <h3 id="cookie-description">We Value Your Privacy</h3>
                <p>
                  We use cookies to enhance your experience, analyse site traffic, and support our marketing efforts.
                  By clicking "Accept All", you consent to our use of cookies. You can customise your preferences or reject optional cookies.
                </p>
              </div>
            </div>
            <div className="cookie-actions">
              <button className="btn btn-ghost btn-sm" onClick={() => setShowSettings(true)}>
                <Settings size={16} strokeWidth={2} />
                Customise
              </button>
              <button className="btn btn-ghost btn-sm" onClick={handleRejectOptional}>
                Reject Optional
              </button>
              <button className="btn btn-primary btn-sm" onClick={handleAcceptAll}>
                Accept All
                <Check size={16} strokeWidth={2.5} />
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {showSettings && (
        <>
          <motion.div
            className="cookie-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => { setShowSettings(false); setShowBanner(true); }}
          />
          <motion.div
            className="cookie-settings"
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.2 }}
            role="dialog"
            aria-modal="true"
            aria-labelledby="settings-title"
          >
            <div className="settings-header">
              <h3 id="settings-title">Cookie Preferences</h3>
              <button className="settings-close" onClick={() => { setShowSettings(false); setShowBanner(true); }} aria-label="Close settings">
                <X size={20} strokeWidth={2} />
              </button>
            </div>
            <div className="settings-body">
              <p className="settings-description">
                Manage your cookie preferences below. Strictly necessary cookies cannot be disabled as they are essential for the website to function.
              </p>

              <div className="settings-list">
                <label className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon necessary">
                      <Shield size={20} strokeWidth={2} />
                    </div>
                    <div className="setting-details">
                      <span className="setting-name">Strictly Necessary</span>
                      <span className="setting-desc">Essential for website functionality, security, and accessibility.</span>
                    </div>
                  </div>
                  <div className="setting-toggle">
                    <input
                      type="checkbox"
                      checked={true}
                      disabled
                      aria-label="Strictly necessary cookies (always enabled)"
                    />
                    <span className="toggle-slider" />
                  </div>
                  <span className="setting-badge">Always On</span>
                </label>

                <label className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon analytics">
                      <BarChart2 size={20} strokeWidth={2} />
                    </div>
                    <div className="setting-details">
                      <span className="setting-name">Analytics</span>
                      <span className="setting-desc">Help us understand how visitors interact with our website (e.g., page views, traffic sources).</span>
                    </div>
                  </div>
                  <div className="setting-toggle">
                    <input
                      type="checkbox"
                      checked={preferences.analytics}
                      onChange={e => setPreferences(p => ({ ...p, analytics: e.target.checked }))}
                      aria-label="Analytics cookies"
                    />
                    <span className="toggle-slider" />
                  </div>
                </label>

                <label className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon marketing">
                      <Megaphone size={20} strokeWidth={2} />
                    </div>
                    <div className="setting-details">
                      <span className="setting-name">Marketing</span>
                      <span className="setting-desc">Used to deliver relevant advertisements and measure campaign effectiveness.</span>
                    </div>
                  </div>
                  <div className="setting-toggle">
                    <input
                      type="checkbox"
                      checked={preferences.marketing}
                      onChange={e => setPreferences(p => ({ ...p, marketing: e.target.checked }))}
                      aria-label="Marketing cookies"
                    />
                    <span className="toggle-slider" />
                  </div>
                </label>
              </div>
            </div>
            <div className="settings-footer">
              <button className="btn btn-ghost" onClick={() => { setShowSettings(false); setShowBanner(true); }}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleCustomizeSave}>
                Save Preferences
                <Check size={16} strokeWidth={2.5} />
              </button>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}