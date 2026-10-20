import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Mail,
  Phone,
  Building2,
  Briefcase,
  Users,
  Calendar,
  Clock,
  CheckCircle2,
  AlertCircle,
  Loader2,
  X,
} from 'lucide-react';
import { submitDemoBooking, DemoBookingData } from '../lib/supabase';
import './DemoBooking.css';

const industries = [
  'Banking & Financial Services',
  'Insurance',
  'Healthcare',
  'E-commerce & Retail',
  'IT & Software Services',
  'Education & EdTech',
  'Telecommunications',
  'Manufacturing',
  'Government & Public Sector',
  'Other',
];

const orgSizes = [
  '1–10 employees',
  '11–50 employees',
  '51–200 employees',
  '201–500 employees',
  '501–1000 employees',
  '1001–5000 employees',
  '5000+ employees',
];

const interestAreas = [
  { id: 'data-mapping', label: 'Data Mapping & Inventory' },
  { id: 'consent-purpose', label: 'Consent & Purpose Validation' },
  { id: 'retention', label: 'Retention Monitoring' },
  { id: 'breach-detection', label: 'Breach Detection & Response' },
  { id: 'ai-assistant', label: 'AI-Assisted Investigation' },
  { id: 'readiness-score', label: 'DPDP Readiness Scoring' },
  { id: 'access-management', label: 'Access Management & IAM' },
];

export function DemoBooking() {
  const [formData, setFormData] = useState<DemoBookingData>({
    full_name: '',
    business_email: '',
    phone_number: '',
    organization_name: '',
    designation: '',
    industry: '',
    organization_size: '',
    preferred_date: '',
    preferred_time: '',
    areas_of_interest: [],
    additional_requirements: '',
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const [submitStatus, setSubmitStatus] = useState<'idle' | 'submitting' | 'success' | 'error'>('idle');
  const [submitMessage, setSubmitMessage] = useState('');
  const [bookingReference, setBookingReference] = useState('');
  const [honeypot, setHoneypot] = useState('');
  const formRef = useRef<HTMLFormElement>(null);

  const minDate = new Date().toISOString().split('T')[0];

  const validateField = (name: keyof DemoBookingData, value: string): string => {
    switch (name) {
      case 'full_name':
        return value.trim().length < 2 ? 'Please enter your full name' : '';
      case 'business_email':
        return !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? 'Please enter a valid business email' : '';
      case 'phone_number':
        return !/^[\d\s\-\+\(\)]{10,}$/.test(value) ? 'Please enter a valid phone number' : '';
      case 'organization_name':
        return value.trim().length < 2 ? 'Please enter your organisation name' : '';
      case 'designation':
        return value.trim().length < 2 ? 'Please enter your designation' : '';
      case 'industry':
        return !value ? 'Please select your industry' : '';
      case 'organization_size':
        return !value ? 'Please select organisation size' : '';
      case 'preferred_date':
        return !value ? 'Please select a preferred date' : '';
      case 'preferred_time':
        return !value ? 'Please select a preferred time' : '';
      case 'areas_of_interest':
        return value.length === 0 ? 'Please select at least one area of interest' : '';
      default:
        return '';
    }
  };

  const handleChange = (name: keyof DemoBookingData, value: string | string[]) => {
    setFormData(prev => ({ ...prev, [name]: value }));
    const error = validateField(name, typeof value === 'string' ? value : value.join(','));
    setErrors(prev => ({ ...prev, [name]: error }));
  };

  const handleBlur = (name: keyof DemoBookingData) => {
    setTouched(prev => ({ ...prev, [name]: true }));
    const error = validateField(name, formData[name] as string);
    setErrors(prev => ({ ...prev, [name]: error }));
  };

  const handleInterestChange = (areaId: string) => {
    setFormData(prev => {
      const current = prev.areas_of_interest;
      const updated = current.includes(areaId)
        ? current.filter(id => id !== areaId)
        : [...current, areaId];
      return { ...prev, areas_of_interest: updated };
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const newErrors: Record<string, string> = {};
    let hasErrors = false;

    (Object.keys(formData) as Array<keyof DemoBookingData>).forEach(key => {
      if (key !== 'additional_requirements') {
        const value = formData[key];
        const stringValue = Array.isArray(value) ? value.join(',') : value;
        const error = validateField(key, stringValue);
        if (error) {
          newErrors[key] = error;
          hasErrors = true;
        }
      }
    });

    if (honeypot) {
      setSubmitStatus('error');
      setSubmitMessage('Submission failed. Please try again.');
      return;
    }

    if (hasErrors) {
      setErrors(newErrors);
      setTouched(Object.keys(formData).reduce((acc, key) => ({ ...acc, [key]: true }), {}));
      return;
    }

    setSubmitStatus('submitting');
    setSubmitMessage('');

    const result = await submitDemoBooking(formData);

    if (result.success) {
      setSubmitStatus('success');
      setBookingReference(result.bookingReference || '');
      setSubmitMessage('Your demo request has been submitted successfully. Our team will contact you to confirm the meeting details.');
      if (formRef.current) formRef.current.reset();
      setFormData({
        full_name: '',
        business_email: '',
        phone_number: '',
        organization_name: '',
        designation: '',
        industry: '',
        organization_size: '',
        preferred_date: '',
        preferred_time: '',
        areas_of_interest: [],
        additional_requirements: '',
      });
      setErrors({});
      setTouched({});
    } else {
      setSubmitStatus('error');
      setSubmitMessage(result.error || 'Unable to submit your request. Please try again later.');
    }
  };

  const handleCloseSuccess = () => {
    setSubmitStatus('idle');
    setBookingReference('');
  };

  return (
    <section id="contact" className="section demo-section" aria-labelledby="demo-heading">
      <div className="container">
        <motion.div
          className="section-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="eyebrow">Get Started</span>
          <h2 id="demo-heading">See How NigraniAI Can Strengthen Your Privacy Monitoring.</h2>
          <p>
            Book a personalised demonstration to explore how NigraniAI helps organisations monitor personal-data processing and improve compliance readiness.
          </p>
        </motion.div>

        <div className="demo-layout">
          <motion.div
            className="demo-info"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="info-card">
              <div className="info-icon">
                <CheckCircle2 size={24} strokeWidth={2} />
              </div>
              <h3>What to Expect</h3>
              <ul className="info-list">
                <li><span>30-minute</span> personalised walkthrough</li>
                <li>Tailored to your <span>industry & use case</span></li>
                <li>Live platform preview with <span>sample data</span></li>
                <li>Q&A with our <span>privacy engineers</span></li>
                <li>No credit card <span>required</span></li>
              </ul>
            </div>

            <div className="info-card">
              <div className="info-icon">
                <Building2 size={24} strokeWidth={2} />
              </div>
              <h3>Who Should Attend</h3>
              <ul className="info-list">
                <li>Data Protection Officers</li>
                <li>Compliance & Risk Teams</li>
                <li>Security & IT Leadership</li>
                <li>Privacy Engineers</li>
                <li>Business Owners & Decision Makers</li>
              </ul>
            </div>

            <div className="contact-info">
              <h3>Prefer to Email?</h3>
              <div className="contact-details">
                <a href="mailto:atharvakadam11056@gmail.com" className="contact-link">
                  <Mail size={18} strokeWidth={2} />
                  <span>atharvakadam11056@gmail.com</span>
                </a>
                <a href="tel:+918788445877" className="contact-link">
                  <Phone size={18} strokeWidth={2} />
                  <span>+91 87884 45877</span>
                </a>
              </div>
            </div>
          </motion.div>

          <motion.div
            className="demo-form-wrapper"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <AnimatePresence mode="wait">
              {submitStatus === 'success' ? (
                <motion.div
                  className="success-state"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ duration: 0.3 }}
                  role="alert"
                >
                  <div className="success-icon">
                    <CheckCircle2 size={48} strokeWidth={2.5} />
                  </div>
                  <h3>Request Submitted Successfully</h3>
                  <p className="booking-ref">Booking Reference: <strong>{bookingReference}</strong></p>
                  <p>{submitMessage}</p>
                  <button className="btn btn-primary" onClick={handleCloseSuccess}>
                    <X size={18} strokeWidth={2.5} />
                    Close
                  </button>
                </motion.div>
              ) : (
                <form ref={formRef} className="demo-form" onSubmit={handleSubmit} noValidate>
                  <div className="form-row">
                    <div className="form-group">
                      <label htmlFor="full_name">Full Name <span className="required">*</span></label>
                      <div className="input-wrapper">
                        <Mail size={18} strokeWidth={2} />
                        <input
                          type="text"
                          id="full_name"
                          name="full_name"
                          value={formData.full_name}
                          onChange={e => handleChange('full_name', e.target.value)}
                          onBlur={() => handleBlur('full_name')}
                          placeholder="John Smith"
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.full_name && !!errors.full_name}
                          aria-describedby={touched.full_name && errors.full_name ? 'full_name-error' : undefined}
                        />
                      </div>
                      {touched.full_name && errors.full_name && (
                        <span id="full_name-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.full_name}
                        </span>
                      )}
                    </div>

                    <div className="form-group">
                      <label htmlFor="business_email">Business Email <span className="required">*</span></label>
                      <div className="input-wrapper">
                        <Mail size={18} strokeWidth={2} />
                        <input
                          type="email"
                          id="business_email"
                          name="business_email"
                          value={formData.business_email}
                          onChange={e => handleChange('business_email', e.target.value)}
                          onBlur={() => handleBlur('business_email')}
                          placeholder="john@company.com"
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.business_email && !!errors.business_email}
                          aria-describedby={touched.business_email && errors.business_email ? 'business_email-error' : undefined}
                        />
                      </div>
                      {touched.business_email && errors.business_email && (
                        <span id="business_email-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.business_email}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="form-row">
                    <div className="form-group">
                      <label htmlFor="phone_number">Phone Number <span className="required">*</span></label>
                      <div className="input-wrapper">
                        <Phone size={18} strokeWidth={2} />
                        <input
                          type="tel"
                          id="phone_number"
                          name="phone_number"
                          value={formData.phone_number}
                          onChange={e => handleChange('phone_number', e.target.value)}
                          onBlur={() => handleBlur('phone_number')}
                          placeholder="+91 98765 43210"
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.phone_number && !!errors.phone_number}
                          aria-describedby={touched.phone_number && errors.phone_number ? 'phone_number-error' : undefined}
                        />
                      </div>
                      {touched.phone_number && errors.phone_number && (
                        <span id="phone_number-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.phone_number}
                        </span>
                      )}
                    </div>

                    <div className="form-group">
                      <label htmlFor="designation">Designation <span className="required">*</span></label>
                      <div className="input-wrapper">
                        <Briefcase size={18} strokeWidth={2} />
                        <input
                          type="text"
                          id="designation"
                          name="designation"
                          value={formData.designation}
                          onChange={e => handleChange('designation', e.target.value)}
                          onBlur={() => handleBlur('designation')}
                          placeholder="Data Protection Officer"
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.designation && !!errors.designation}
                          aria-describedby={touched.designation && errors.designation ? 'designation-error' : undefined}
                        />
                      </div>
                      {touched.designation && errors.designation && (
                        <span id="designation-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.designation}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="form-row">
                    <div className="form-group">
                      <label htmlFor="organization_name">Organisation Name <span className="required">*</span></label>
                      <div className="input-wrapper">
                        <Building2 size={18} strokeWidth={2} />
                        <input
                          type="text"
                          id="organization_name"
                          name="organization_name"
                          value={formData.organization_name}
                          onChange={e => handleChange('organization_name', e.target.value)}
                          onBlur={() => handleBlur('organization_name')}
                          placeholder="Acme Corporation"
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.organization_name && !!errors.organization_name}
                          aria-describedby={touched.organization_name && errors.organization_name ? 'organization_name-error' : undefined}
                        />
                      </div>
                      {touched.organization_name && errors.organization_name && (
                        <span id="organization_name-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.organization_name}
                        </span>
                      )}
                    </div>

                    <div className="form-group">
                      <label htmlFor="industry">Industry <span className="required">*</span></label>
                      <div className="select-wrapper">
                        <Building2 size={18} strokeWidth={2} />
                        <select
                          id="industry"
                          name="industry"
                          value={formData.industry}
                          onChange={e => handleChange('industry', e.target.value)}
                          onBlur={() => handleBlur('industry')}
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.industry && !!errors.industry}
                          aria-describedby={touched.industry && errors.industry ? 'industry-error' : undefined}
                        >
                          <option value="">Select Industry</option>
                          {industries.map(industry => (
                            <option key={industry} value={industry}>{industry}</option>
                          ))}
                        </select>
                      </div>
                      {touched.industry && errors.industry && (
                        <span id="industry-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.industry}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="form-row">
                    <div className="form-group">
                      <label htmlFor="organization_size">Organisation Size <span className="required">*</span></label>
                      <div className="select-wrapper">
                        <Users size={18} strokeWidth={2} />
                        <select
                          id="organization_size"
                          name="organization_size"
                          value={formData.organization_size}
                          onChange={e => handleChange('organization_size', e.target.value)}
                          onBlur={() => handleBlur('organization_size')}
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.organization_size && !!errors.organization_size}
                          aria-describedby={touched.organization_size && errors.organization_size ? 'organization_size-error' : undefined}
                        >
                          <option value="">Select Size</option>
                          {orgSizes.map(size => (
                            <option key={size} value={size}>{size}</option>
                          ))}
                        </select>
                      </div>
                      {touched.organization_size && errors.organization_size && (
                        <span id="organization_size-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.organization_size}
                        </span>
                      )}
                    </div>

                    <div className="form-group">
                      <label htmlFor="preferred_date">Preferred Demo Date <span className="required">*</span></label>
                      <div className="input-wrapper">
                        <Calendar size={18} strokeWidth={2} />
                        <input
                          type="date"
                          id="preferred_date"
                          name="preferred_date"
                          value={formData.preferred_date}
                          onChange={e => handleChange('preferred_date', e.target.value)}
                          onBlur={() => handleBlur('preferred_date')}
                          min={minDate}
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.preferred_date && !!errors.preferred_date}
                          aria-describedby={touched.preferred_date && errors.preferred_date ? 'preferred_date-error' : undefined}
                        />
                      </div>
                      {touched.preferred_date && errors.preferred_date && (
                        <span id="preferred_date-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.preferred_date}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="form-row">
                    <div className="form-group">
                      <label htmlFor="preferred_time">Preferred Time <span className="required">*</span></label>
                      <div className="select-wrapper">
                        <Clock size={18} strokeWidth={2} />
                        <select
                          id="preferred_time"
                          name="preferred_time"
                          value={formData.preferred_time}
                          onChange={e => handleChange('preferred_time', e.target.value)}
                          onBlur={() => handleBlur('preferred_time')}
                          disabled={submitStatus === 'submitting'}
                          aria-invalid={touched.preferred_time && !!errors.preferred_time}
                          aria-describedby={touched.preferred_time && errors.preferred_time ? 'preferred_time-error' : undefined}
                        >
                          <option value="">Select Time (IST)</option>
                          {['09:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00'].map(time => (
                            <option key={time} value={time}>{time} IST</option>
                          ))}
                        </select>
                      </div>
                      {touched.preferred_time && errors.preferred_time && (
                        <span id="preferred_time-error" className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.preferred_time}
                        </span>
                      )}
                    </div>

                    <div className="form-group full-width" style={{ gridColumn: '1 / -1' }}>
                      <label>Areas of Interest <span className="required">*</span></label>
                      <div className="checkbox-group" role="group" aria-labelledby="interests-label">
                        {interestAreas.map(area => (
                          <label key={area.id} className="checkbox-label">
                            <input
                              type="checkbox"
                              value={area.id}
                              checked={formData.areas_of_interest.includes(area.id)}
                              onChange={() => handleInterestChange(area.id)}
                              disabled={submitStatus === 'submitting'}
                            />
                            <span className="checkbox-custom">
                              <CheckCircle2 size={16} strokeWidth={2.5} />
                            </span>
                            <span>{area.label}</span>
                          </label>
                        ))}
                      </div>
                      {touched.areas_of_interest && errors.areas_of_interest && (
                        <span className="error-message" role="alert">
                          <AlertCircle size={14} strokeWidth={2} /> {errors.areas_of_interest}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="form-group full-width" style={{ gridColumn: '1 / -1' }}>
                    <label htmlFor="additional_requirements">Additional Requirements (Optional)</label>
                    <textarea
                      id="additional_requirements"
                      name="additional_requirements"
                      value={formData.additional_requirements}
                      onChange={e => handleChange('additional_requirements', e.target.value)}
                      placeholder="Any specific requirements, compliance focus areas, or questions for the demo..."
                      rows={4}
                      disabled={submitStatus === 'submitting'}
                    />
                  </div>

                  <input type="hidden" name="honeypot" value={honeypot} onChange={e => setHoneypot(e.target.value)} tabIndex={-1} autoComplete="off" />

                  {submitStatus === 'error' && (
                    <div className="form-error" role="alert">
                      <AlertCircle size={18} strokeWidth={2} />
                      <span>{submitMessage}</span>
                    </div>
                  )}

                  <button
                    type="submit"
                    className="btn btn-primary btn-lg form-submit"
                    disabled={submitStatus === 'submitting'}
                  >
                    {submitStatus === 'submitting' ? (
                      <>
                        <Loader2 size={18} strokeWidth={2.5} className="spinning" />
                        Submitting...
                      </>
                    ) : (
                      'Submit Demo Request'
                    )}
                  </button>

                  <p className="form-disclaimer">
                    This is a demo request, not a confirmed calendar booking. Our team will contact you to confirm the meeting details.
                  </p>
                </form>
              )}
            </AnimatePresence>
          </motion.div>
        </div>
      </div>
    </section>
  );
}