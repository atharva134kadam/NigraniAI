import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, ChevronUp, Scale, Shield } from 'lucide-react';
import { useState } from 'react';
import './DPDPASection.css';

const faqItems = [
  {
    question: 'What is the DPDP Act?',
    answer: (
      <>
        <p>
          India&apos;s Digital Personal Data Protection Act, 2023 establishes a legal framework for processing digital personal data in India. It applies to the processing of digital personal data within India, as well as processing outside India if it relates to offering goods or services to individuals in India.
        </p>
        <p><strong>Its purpose, in simple terms:</strong></p>
        <ul>
          <li><strong>Protecting individuals&apos; digital personal data</strong> — giving people control over their information.</li>
          <li><strong>Defining responsibilities for organisations</strong> (Data Fiduciaries) that process personal data.</li>
          <li><strong>Promoting transparency and accountability</strong> in how personal data is handled.</li>
          <li><strong>Establishing rights and obligations</strong> related to digital personal data.</li>
        </ul>
      </>
    ),
  },
  {
    question: 'Who are the key stakeholders?',
    answer: (
      <>
        <ul>
          <li><strong>Data Principal:</strong> The individual to whom the personal data relates (e.g., a customer, employee, user).</li>
          <li><strong>Data Fiduciary:</strong> Any person or organisation that determines the purpose and means of processing personal data (e.g., a company collecting customer data).</li>
          <li><strong>Data Processor:</strong> Any person or organisation that processes personal data on behalf of a Data Fiduciary.</li>
          <li><strong>Data Protection Board of India:</strong> The regulatory body established to adjudicate non-compliance and impose penalties.</li>
        </ul>
      </>
    ),
  },
  {
    question: 'What are the important concepts under the Act?',
    answer: (
      <>
        <ul>
          <li><strong>Consent:</strong> Free, specific, informed, unconditional, and unambiguous agreement. Must be withdrawable.</li>
          <li><strong>Purpose Limitation:</strong> Personal data must be processed only for the specified purpose for which it was collected.</li>
          <li><strong>Notice and Transparency:</strong> Data Fiduciaries must give clear notice about what data is collected, why, and how it will be used.</li>
          <li><strong>Reasonable Security Safeguards:</strong> Organisations must implement appropriate technical and organisational measures to protect personal data.</li>
          <li><strong>Personal Data Breach:</strong> Any unauthorised processing, accidental disclosure, loss, or destruction of personal data.</li>
          <li><strong>Data Retention and Erasure:</strong> Data must be erased when the purpose is fulfilled or consent is withdrawn, unless retention is required by law.</li>
          <li><strong>Rights of Data Principals:</strong> Right to access, correction, erasure, grievance redressal, and nomination.</li>
        </ul>
      </>
    ),
  },
  {
    question: 'Why is the DPDP Act important for organisations?',
    answer: (
      <>
        <p>Organisations need to understand:</p>
        <ul>
          <li><strong>What personal data they collect</strong> — across all systems, applications, and databases.</li>
          <li><strong>Why they process it</strong> — ensuring every processing activity has a lawful basis and declared purpose.</li>
          <li><strong>How they protect it</strong> — implementing reasonable security safeguards and breach detection.</li>
          <li><strong>How they manage consent</strong> — obtaining valid consent, maintaining records, and honouring withdrawals.</li>
          <li><strong>How they handle personal-data breaches</strong> — detection, investigation, and notification obligations.</li>
          <li><strong>How they manage retention and erasure</strong> — ensuring data is not kept longer than necessary.</li>
        </ul>
      </>
    ),
  },
  {
    question: 'Where does NigraniAI fit in?',
    answer: (
      <>
        <p>
          NigraniAI helps organisations gain visibility into personal-data processing, monitor relevant activities, identify potential compliance issues, and support privacy investigations and readiness.
        </p>
        <p>
          <strong>It is important to understand:</strong>
        </p>
        <ul>
          <li>NigraniAI is a <strong>monitoring and intelligence platform</strong>, not a legal advisor.</li>
          <li>It does <strong>not guarantee legal compliance</strong> with the DPDP Act or any regulation.</li>
          <li>It does <strong>not replace qualified legal professionals</strong> for legal interpretation.</li>
          <li>Organisations should <strong>consult qualified legal professionals</strong> for legal advice specific to their circumstances.</li>
        </ul>
        <p>
          NigraniAI&apos;s capabilities — data mapping, consent & purpose validation, retention monitoring, breach detection, AI-assisted investigation, and DPDP readiness scoring — are designed to <strong>support</strong> your compliance programme by providing continuous, evidence-based visibility into actual system activity.
        </p>
      </>
    ),
  },
];

export function DPDPASection() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  const toggleFAQ = (index: number) => {
    setOpenIndex(prev => prev === index ? null : index);
  };

  return (
    <section id="dpdpa" className="section dpdpa-section" aria-labelledby="dpdpa-heading">
      <div className="container">
        <motion.div
          className="section-header"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
        >
          <span className="eyebrow">Regulatory Context</span>
          <h2 id="dpdpa-heading">Understanding India&apos;s Digital Personal Data Protection Act.</h2>
          <p>
            The DPDP Act, 2023 establishes a comprehensive framework for digital personal data processing in India.
            This section explains the key concepts and why they matter for your organisation.
          </p>
        </motion.div>

        <div className="dpdpa-content">
          <motion.div
            className="dpdpa-intro"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="intro-card">
              <div className="intro-icon">
                <Scale size={28} strokeWidth={2} />
              </div>
              <h3>What This Means for Your Organisation</h3>
              <p>
                The DPDP Act shifts the responsibility onto organisations to demonstrate how they collect, use, protect, and erase personal data.
                Manual, periodic compliance reviews are no longer sufficient. Continuous visibility into actual data processing activity is essential.
              </p>
            </div>
            <div className="intro-card">
              <div className="intro-icon">
                <Shield size={28} strokeWidth={2} />
              </div>
              <h3>NigraniAI&apos;s Role</h3>
              <p>
                NigraniAI provides the monitoring layer — analysing real application and database activity to help you understand what personal data is being processed, whether it aligns with consent and purpose, and where risks may exist.
              </p>
            </div>
          </motion.div>

          <motion.div
            className="dpdpa-faq"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <h3 className="faq-title">Key Questions About the DPDP Act</h3>
            <div className="faq-list">
              {faqItems.map((item, index) => (
                <motion.div
                  key={index}
                  className="faq-item"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.3 + index * 0.05 }}
                >
                  <button
                    className="faq-question"
                    onClick={() => toggleFAQ(index)}
                    aria-expanded={openIndex === index}
                    aria-controls={`faq-answer-${index}`}
                    type="button"
                  >
                    <span className="faq-question-text">{item.question}</span>
                    <span className="faq-icon" aria-hidden="true">
                      {openIndex === index ? (
                        <ChevronUp size={20} strokeWidth={2.5} />
                      ) : (
                        <ChevronDown size={20} strokeWidth={2.5} />
                      )}
                    </span>
                  </button>
                  <AnimatePresence>
                    {openIndex === index && (
                      <motion.div
                        id={`faq-answer-${index}`}
                        className="faq-answer"
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        transition={{ duration: 0.3, ease: 'easeInOut' }}
                      >
                        <div className="faq-answer-content">{item.answer}</div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}