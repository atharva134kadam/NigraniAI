import { BrowserRouter } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Hero } from './components/Hero';
import { ProblemSection } from './components/ProblemSection';
import { Capabilities } from './components/Capabilities';
import { HowItWorks } from './components/HowItWorks';
import { DPDPASection } from './components/DPDPASection';
import { WhyNigraniAI } from './components/WhyNigraniAI';
import { About } from './components/About';
import { DPDPCountdown } from './components/DPDPCountdown';
import { DemoBooking } from './components/DemoBooking';
import { CookieConsent } from './components/CookieConsent';
import { Footer } from './components/Footer';
import './index.css';

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Navbar />
        <main id="main-content">
          <Hero />
          <ProblemSection />
          <Capabilities />
          <HowItWorks />
          <DPDPASection />
          <WhyNigraniAI />
          <About />
          <DPDPCountdown />
          <DemoBooking />
        </main>
        <Footer />
        <CookieConsent />
      </div>
    </BrowserRouter>
  );
}

export default App;