/**
 * components/AIAnalysisPanel.js - EXECUTIVE INTELLIGENCE ENGINE
 * Updated: 2026-01-20 - INTEGRATION: Polar Paywall & Trial Flow
 */
import React, { useState, useEffect, useMemo, useRef } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { 
    FaRedo, FaSearch, FaRobot, FaVolumeUp, FaLayerGroup
} from 'react-icons/fa';
import { 
    FiShield, FiZap, FiCpu, FiX, FiTarget, FiCheckCircle, FiFileText, FiTrendingUp, FiActivity, FiLock, FiArrowRight
} from 'react-icons/fi';

const API_BASE_URL = "https://ai-data-analyst-backend-1nuw.onrender.com";

const AudioWaveform = ({ color = "#bc13fe" }) => (
    <div className="flex items-center gap-1 h-4">
        {[...Array(4)].map((_, i) => (
            <motion.div
                key={i}
                animate={{ height: [4, 16, 8, 14, 4] }}
                transition={{ duration: 0.8, repeat: Infinity, delay: i * 0.1, ease: "easeInOut" }}
                className="w-1 rounded-full"
                style={{ backgroundColor: color }}
            />
        ))}
    </div>
);

const InsightCard = ({ title, content, icon: Icon, isPurple, onClick }) => (
    <div 
        onClick={onClick}
        className="relative group bg-[#111116] border border-white/5 rounded-[2rem] overflow-hidden flex flex-col transition-all duration-300 hover:border-white/20 hover:translate-y-[-4px] shadow-2xl cursor-pointer"
    >
        <div className="h-1.5 w-full opacity-80" style={{ backgroundColor: isPurple ? '#bc13fe' : '#a5b4fc' }} />
        <div className="p-8 flex flex-col h-full">
            <div className="flex justify-between items-start mb-6">
                <div className={`p-3 rounded-xl bg-white/5 ${isPurple ? 'text-[#bc13fe]' : 'text-indigo-400'}`}>
                    <Icon size={20} />
                </div>
                <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-full border border-white/10">
                    <div className={`w-1.5 h-1.5 rounded-full animate-pulse ${isPurple ? 'bg-[#bc13fe]' : 'bg-indigo-400'}`} />
                    <span className="text-[9px] font-bold text-white/60 uppercase tracking-widest">Live Analysis</span>
                </div>
            </div>
            <h4 className="text-white font-bold text-lg mb-3 tracking-tight group-hover:text-indigo-300 transition-colors">{title}</h4>
            <p className="text-white text-sm leading-relaxed mb-8 line-clamp-4 font-medium">{content || "Analyzing data vectors..."}</p>
            <div className="space-y-3 mb-8 flex-1">
                <div className="flex items-center gap-3 text-[10px] text-white uppercase tracking-[0.2em] font-bold">
                    <FiCheckCircle className={isPurple ? 'text-[#bc13fe]' : 'text-indigo-400'} /> Verified Insight
                </div>
                <div className="flex items-center gap-3 text-[10px] text-white uppercase tracking-[0.2em] font-bold">
                    <FiCheckCircle className={isPurple ? 'text-[#bc13fe]' : 'text-indigo-400'} /> ROI Aligned
                </div>
            </div>
            <button className={`w-full py-4 rounded-xl text-[11px] font-black uppercase tracking-[0.2em] transition-all ${isPurple ? 'bg-[#bc13fe]/10 text-[#bc13fe] border border-[#bc13fe]/20' : 'bg-white/5 text-white/40 border border-white/10'}`}>
                View Deep Intel
            </button>
        </div>
    </div>
);

const TypewriterText = ({ text, delay = 5 }) => {
    const [displayedText, setDisplayedText] = useState("");
    useEffect(() => {
        setDisplayedText(""); 
        if (!text) return;
        let currentIndex = 0;
        const timer = setInterval(() => {
            if (currentIndex < text.length) {
                setDisplayedText(text.substring(0, currentIndex + 1));
                currentIndex++;
            } else { clearInterval(timer); }
        }, delay);
        return () => clearInterval(timer);
    }, [text, delay]);
    return <span>{displayedText}</span>;
};

const AIAnalysisPanel = ({ datasets = [], onUpdateAI }) => {
    const [loading, setLoading] = useState(false);
    const [analysisPhase, setAnalysisPhase] = useState(0);
    const [expandedCard, setExpandedCard] = useState(null); 
    const [isFullReportOpen, setIsFullReportOpen] = useState(false);
    const [isSpeaking, setIsSpeaking] = useState(false);
    const [intelligenceMode, setIntelligenceMode] = useState(null);
    const [showModeSelector, setShowModeSelector] = useState(false);
    const [showPaywall, setShowPaywall] = useState(false);
    const [isRedirecting, setIsRedirecting] = useState(false);
    
    const panelRef = useRef(null);
    const userToken = localStorage.getItem("adt_token");
    const userProfile = useMemo(() => {
        const stored = localStorage.getItem("adt_profile");
        return stored ? JSON.parse(stored) : null;
    }, []);

    const aiInsights = datasets[0]?.aiStorage;

    const phases = useMemo(() => [
        "Initializing AI Analyst...",
        `Aligning with ${userProfile?.organization || 'Corporate'} standards...`,
        "Syncing Neural models...",
        intelligenceMode === 'correlation' ? "Mapping cross-dataset dependencies..." : 
        intelligenceMode === 'compare' ? "Calculating performance variance..." : "Auditing standalone silos...",
        "Simulating ROI Impact...",
        "Finalizing Strategic Report..."
    ], [userProfile, intelligenceMode]);

    // Reset redirecting state when paywall is closed
    useEffect(() => {
        if (!showPaywall) {
            setIsRedirecting(false);
        }
    }, [showPaywall]);

    useEffect(() => {
        if (datasets.length > 1 && !aiInsights && !loading) {
            // Wait for user to click button instead of auto-opening
        } else if (datasets.length === 1 && !intelligenceMode && !loading && !aiInsights) {
            setIntelligenceMode('standalone');
        }
    }, [datasets.length, loading, aiInsights]);

    useEffect(() => {
        window.speechSynthesis.getVoices();
    }, []);

    useEffect(() => {
        let interval;
        if (loading) {
            interval = setInterval(() => {
                setAnalysisPhase((prev) => (prev < phases.length - 1 ? prev + 1 : prev));
            }, 2000);
        } else { setAnalysisPhase(0); }
        return () => clearInterval(interval);
    }, [loading, phases.length]);

    const handleStartTrial = async () => {
        setIsRedirecting(true);
        try {
            const res = await axios.post(`${API_BASE_URL}/billing/start-trial`, {}, {
                headers: { Authorization: `Bearer ${userToken}` }
            });
            if (res.data.checkout_url) {
                window.location.href = res.data.checkout_url;
            }
        } catch (err) {
            console.error("Billing redirect failed", err);
            setIsRedirecting(false);
        }
    };

    const toggleSpeech = (textOverride) => {
        if (isSpeaking) {
            window.speechSynthesis.cancel();
            setIsSpeaking(false);
            return;
        }

        let contentToRead = textOverride;
        if (isFullReportOpen) {
            contentToRead = `Right... Let's take a look at the strategic REPORT. First, the Executive Summary: ${aiInsights.summary}. Moving on... our primary discovery found that ${aiInsights.root_cause}. Regarding the potential risks, we've identified the following: ${aiInsights.risk}. On a more positive note; the growth opportunity is significant: ${aiInsights.opportunity}. Finally, our tactical priority will be: ${aiInsights.action}. That concludes the board briefing.`;
        }

        const utterance = new SpeechSynthesisUtterance(contentToRead);
        const voices = window.speechSynthesis.getVoices();
        const britishVoice = voices.find(v => 
            (v.lang === 'en-GB' || v.lang.startsWith('en-GB')) && 
            (v.name.includes('Female') || v.name.includes('UK') || v.name.includes('Hazel') || v.name.includes('Serena'))
        );

        utterance.voice = britishVoice || voices[0];
        utterance.rate = 0.85; 
        utterance.pitch = 1.1;
        
        utterance.onstart = () => setIsSpeaking(true);
        utterance.onend = () => setIsSpeaking(false);
        utterance.onerror = () => setIsSpeaking(false);

        window.speechSynthesis.speak(utterance);
    };

    const runAnalysis = async (selectedMode) => {
        if (datasets.length === 0 || !userToken) return;
        setLoading(true);
        try {
            const contextBundle = datasets.map(ds => ({ 
                id: ds.id, 
                name: ds.name, 
                metrics: ds.metrics 
            }));

            const response = await axios.post(`${API_BASE_URL}/ai/analyze`, { 
                context: contextBundle,
                strategy: selectedMode || 'standalone' 
            }, { 
                headers: { Authorization: `Bearer ${userToken}` } 
            });

            onUpdateAI(datasets[0].id, response.data);
        } catch (error) { 
            console.error("AI Analysis failed:", error); 
        } finally { 
            setLoading(false); 
        }
    };

    const handleSelectMode = (mode) => {
        setIntelligenceMode(mode);
        setShowModeSelector(false);
        runAnalysis(mode);
    };

    const handleInitialClick = () => {
        // MONETIZATION CHECK
        if (!userProfile?.is_trial_active) {
            setShowPaywall(true);
            return;
        }

        if (datasets.length > 1) {
            setShowModeSelector(true);
        } else {
            handleSelectMode('standalone');
        }
    };

    return (
        <div ref={panelRef} className="relative overflow-hidden px-0 py-8 md:py-16 transition-all duration-700 min-h-[600px]">
            <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-indigo-600/5 blur-[140px] rounded-full pointer-events-none" />

            {/* PAYWALL MODAL */}
            <AnimatePresence>
                {showPaywall && (
                    <motion.div 
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[10005] bg-black/80 backdrop-blur-2xl flex items-center justify-center p-4"
                    >
                        <motion.div
                            initial={{ scale: 0.9, opacity: 0, y: 20 }} animate={{ scale: 1, opacity: 1, y: 0 }}
                            className="w-full max-w-lg bg-[#0f0f13] border border-white/10 rounded-[3rem] p-10 text-center shadow-3xl overflow-hidden relative"
                        >
                            {/* Close Button */}
                            <button 
                                onClick={() => setShowPaywall(false)}
                                className="absolute top-8 right-8 text-white/40 hover:text-white transition-colors p-2 rounded-full hover:bg-white/5"
                            >
                                <FiX size={24} />
                            </button>

                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-500 via-purple-500 to-indigo-500" />
                            <div className="mb-8 flex justify-center">
                                <div className="w-20 h-20 bg-indigo-500/10 rounded-3xl flex items-center justify-center border border-indigo-500/20">
                                    <FiLock className="text-indigo-400 text-3xl" />
                                </div>
                            </div>
                            <h2 className="text-white text-3xl font-black mb-4 tracking-tight uppercase">Neural Core Locked</h2>
                            <p className="text-white/60 mb-10 leading-relaxed">Advanced synergy audits and correlation mapping require an active Pro license. Start your 7-day trial to unlock full strategic intelligence.</p>
                            
                            <div className="space-y-4">
                                <button 
                                    onClick={handleStartTrial}
                                    className="w-full py-6 bg-indigo-500 hover:bg-indigo-400 text-white rounded-2xl font-black uppercase tracking-widest transition-all flex items-center justify-center gap-3 group shadow-xl shadow-indigo-500/20"
                                >
                                    {isRedirecting ? "Connecting to Polar..." : (
                                        <>Start 7 Days Free <FiArrowRight className="group-hover:translate-x-1 transition-transform" /></>
                                    )}
                                </button>
                                <button 
                                    onClick={() => setShowPaywall(false)}
                                    className="w-full py-4 text-white/30 hover:text-white/60 text-[11px] font-bold uppercase tracking-[0.2em] transition-all"
                                >
                                    Review data first
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {showModeSelector && datasets.length > 1 && (
                    <motion.div 
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[9999] bg-black/70 backdrop-blur-xl flex items-center justify-center p-4"
                    >
                        <motion.div
                            initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
                            className="w-full max-w-xl bg-[#111116] border border-white/10 rounded-3xl p-6 md:p-10 shadow-2xl mx-auto"
                        >
                            <div className="flex justify-between items-center mb-8">
                                <div className="flex items-center gap-3">
                                    <div className="p-3 rounded-2xl bg-white/5 border border-white/10">
                                        <FaLayerGroup className="text-indigo-400" size={26} />
                                    </div>
                                    <h2 className="text-white font-black text-lg md:text-2xl tracking-tight">Intelligence Strategy</h2>
                                </div>
                                <button onClick={() => setShowModeSelector(false)} className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white">
                                    <FiX size={18} />
                                </button>
                            </div>
                            <p className="text-white/50 text-sm md:text-base mb-8">System detected {datasets.length} data streams. Configure neural synthesis mode.</p>
                            <div className="grid grid-cols-1 gap-4">
                                <button onClick={() => handleSelectMode('correlation')} className="p-5 rounded-2xl bg-white/5 border border-white/10 hover:border-indigo-400 hover:bg-indigo-500/5 transition-all text-left group">
                                    <FiZap className="text-indigo-400 mb-3 group-hover:scale-110 transition-transform" size={22} />
                                    <h4 className="text-white font-bold mb-1 text-sm md:text-base">Cross-Correlation</h4>
                                    <p className="text-white/40 text-[10px] uppercase tracking-[0.2em]">Map cross-stream dependencies</p>
                                </button>
                                <button onClick={() => handleSelectMode('compare')} className="p-5 rounded-2xl bg-white/5 border border-white/10 hover:border-emerald-400 hover:bg-emerald-500/5 transition-all text-left group">
                                    <FiTarget className="text-emerald-400 mb-3 group-hover:scale-110 transition-transform" size={22} />
                                    <h4 className="text-white font-bold mb-1 text-sm md:text-base">Comparative Benchmark</h4>
                                    <p className="text-white/40 text-[10px] uppercase tracking-[0.2em]">Analyze performance deltas</p>
                                </button>
                                <button onClick={() => handleSelectMode('standalone')} className="p-5 rounded-2xl bg-white/5 border border-white/10 hover:border-white/40 hover:bg-white/5 transition-all text-left group">
                                    <FiCpu className="text-white/50 mb-3 group-hover:scale-110 transition-transform" size={22} />
                                    <h4 className="text-white font-bold mb-1 text-sm md:text-base">Independent Streams</h4>
                                    <p className="text-white/40 text-[10px] uppercase tracking-[0.2em]">Autonomous silo deep-dive</p>
                                </button>
                            </div>
                            <button onClick={() => setShowModeSelector(false)} className="mt-6 w-full text-center text-white/30 hover:text-white/60 text-[10px] uppercase tracking-widest transition-colors">Continue without choosing</button>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>

            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-8 mb-16 relative z-10">
                <div className="flex items-center gap-6">
                    <div className="h-16 w-16 bg-white/5 border border-white/10 rounded-2xl flex items-center justify-center shadow-inner">
                        <FiCpu className="text-indigo-400 w-8 h-8" />
                    </div>
                    <div>
                        <h2 className="text-[13px] font-black uppercase tracking-[0.6em] text-white">
                            {userProfile?.organization || "STRATEGIC"} <span className="text-indigo-400">INTELLIGENCE</span>
                        </h2>
                        <div className="flex items-center gap-3 mt-2">
                            <div className={`w-2 h-2 rounded-full ${loading ? 'bg-indigo-400 animate-pulse' : 'bg-emerald-500'}`} />
                            <span className="text-[10px] text-white/70 font-bold uppercase tracking-widest">
                                {loading ? "Computing Logic" : intelligenceMode ? `${intelligenceMode.toUpperCase()} MODE ACTIVE` : "Decision Support Active"}
                            </span>
                        </div>
                    </div>
                </div>
                {aiInsights && !loading && (
                    <div className="flex items-center gap-4">
                        <button onClick={() => setIsFullReportOpen(true)} className="flex items-center gap-3 px-10 py-4 bg-indigo-500 text-white rounded-xl text-[15px] font-black uppercase tracking-widest hover:bg-white hover:text-black transition-all shadow-lg shadow-indigo-500/20">
                           <FiFileText /> View full report
                        </button>
                        {datasets.length > 1 && (
                            <button onClick={() => setShowModeSelector(true)} className="flex items-center gap-3 px-8 py-4 bg-white/5 border border-white/10 text-white rounded-xl text-[11px] font-black uppercase tracking-widest hover:bg-white hover:text-black transition-all">
                                <FaRedo className="text-[9px]" /> Strategic Switch
                            </button>
                        )}
                    </div>
                )}
            </div>

            <AnimatePresence mode="wait">
                {loading ? (
                    <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="py-48 flex flex-col items-center justify-center relative z-10"> 
                        <motion.div animate={{ rotate: 360 }} transition={{ duration: 4, repeat: Infinity, ease: "linear" }}>
                            <FiCpu className="text-indigo-400 mb-10 w-20 h-20 opacity-40" />
                        </motion.div>
                        <h3 className="text-white/80 text-[12px] font-bold uppercase tracking-[0.8em] text-center">{phases[analysisPhase]}</h3>
                    </motion.div>
                ) : aiInsights ? (
                    <motion.div key="results" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-12 relative z-10">
                        <div className="p-12 md:p-16 rounded-[3rem] bg-[#111116] border border-white/5 shadow-2xl relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-indigo-500/[0.07] via-transparent to-purple-500/[0.07] pointer-events-none" />
                            <div className="absolute -top-24 -right-24 w-64 h-64 bg-indigo-500/10 blur-[80px] rounded-full" />
                            
                            <div className="relative z-10">
                                <div className="flex items-center gap-3 mb-10">
                                    <div className="h-1 w-12 bg-indigo-400 rounded-full" />
                                    <span className="text-indigo-400 text-[12px] font-black uppercase tracking-[0.6em]">EXECUTIVE SUMMARY</span>
                                    {intelligenceMode === 'correlation' && (
                                        <span className="ml-auto bg-indigo-500/20 text-indigo-400 text-[9px] font-bold px-3 py-1 rounded-full border border-indigo-500/30 tracking-widest">NEURAL CORRELATION</span>
                                    )}
                                    {intelligenceMode === 'standalone' && (
                                        <span className="ml-auto bg-white/5 text-white/40 text-[9px] font-bold px-3 py-1 rounded-full border border-white/10 tracking-widest">INDEPENDENT AUDIT</span>
                                    )}
                                </div>
                                
                                <div className="text-2xl md:text-3xl text-white font-medium leading-[1.5] tracking-tight max-w-5xl mb-12">
                                    <TypewriterText text={aiInsights.summary} />
                                </div>

                                <div className="flex flex-wrap gap-4 pt-8 border-t border-white/5">
                                    <div className="flex items-center gap-4 px-6 py-4 bg-white/5 rounded-2xl border border-white/10 group hover:border-emerald-500/50 transition-all">
                                        <div className="p-2 bg-emerald-500/10 rounded-lg text-emerald-400">
                                            <FiTrendingUp size={18} />
                                        </div>
                                        <div>
                                            <p className="text-[9px] text-white/40 uppercase tracking-widest font-black">Projected ROI Impact</p>
                                            <p className="text-white font-bold text-sm uppercase">{aiInsights.roi_impact || "Calculating..."}</p>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4 px-6 py-4 bg-white/5 rounded-2xl border border-white/10 group hover:border-indigo-500/50 transition-all">
                                        <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
                                            <FiActivity size={18} />
                                        </div>
                                        <div>
                                            <p className="text-[9px] text-white/40 uppercase tracking-widest font-black">Neural Confidence</p>
                                            <p className="text-white font-bold text-sm uppercase">{aiInsights.confidence || "94.2%"}</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                            <InsightCard title="Primary Root Cause" content={aiInsights.root_cause} icon={FaSearch} isPurple={false} onClick={() => setExpandedCard("root")} />
                            <InsightCard title="Risk Exposure" content={aiInsights.risk} icon={FiShield} isPurple={true} onClick={() => setExpandedCard("risk")} />
                            <InsightCard title="Growth Opportunity" content={aiInsights.opportunity} icon={FaRobot} isPurple={false} onClick={() => setExpandedCard("opp")} />
                            <InsightCard title="Recommended Action" content={aiInsights.action} icon={FiTarget} isPurple={true} onClick={() => setExpandedCard("action")} />
                        </div>
                    </motion.div>
                ) : (
                    <div className="py-48 flex flex-col items-center justify-center relative z-10">
                        <button 
                            onClick={handleInitialClick}
                            className="px-12 py-6 bg-indigo-500 text-white rounded-2xl font-black uppercase tracking-widest hover:scale-105 transition-all shadow-2xl shadow-indigo-500/40"
                        >
                            Initialize Neural Analysis
                        </button>
                    </div>
                )}
            </AnimatePresence>

            {/* Modals for Expanded Cards and Full Report */}
            <AnimatePresence>
                {expandedCard && (
                    <motion.div 
                        initial={{ opacity: 0 }} 
                        animate={{ opacity: 1 }} 
                        exit={{ opacity: 0 }} 
                        className="fixed inset-0 z-[10000] bg-[#0a0a0f]/90 backdrop-blur-xl flex items-center justify-center p-6 md:pl-[300px]"
                    >
                        <div className="max-w-4xl w-full bg-[#111116] border border-white/10 rounded-[3rem] p-12 relative shadow-2xl overflow-y-auto max-h-[90vh]">
                            <button onClick={() => setExpandedCard(null)} className="absolute top-6 right-6 text-white/60 hover:text-white transition-colors"><FiX size={26} /></button>
                            <h3 className="text-white text-2xl font-bold mb-6">
                                {expandedCard === "root" && "Primary Root Cause"}
                                {expandedCard === "risk" && "Risk Exposure"}
                                {expandedCard === "opp" && "Growth Opportunity"}
                                {expandedCard === "action" && "Recommended Action"}
                            </h3>
                            <p className="text-white/80 text-lg leading-relaxed font-light">
                                {expandedCard === "root" && aiInsights.root_cause}
                                {expandedCard === "risk" && aiInsights.risk}
                                {expandedCard === "opp" && aiInsights.opportunity}
                                {expandedCard === "action" && aiInsights.action}
                            </p>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <AnimatePresence>
                {isFullReportOpen && (
                    <motion.div 
                        initial={{ opacity: 0 }} 
                        animate={{ opacity: 1 }} 
                        exit={{ opacity: 0 }} 
                        className="fixed inset-0 z-[10001] bg-[#0b0b11]/95 backdrop-blur-2xl p-6 md:p-10 md:pl-[320px] flex flex-col overflow-y-auto"
                    >
                        <div className="max-w-6xl mx-auto w-full">
                            <div className="flex justify-between items-center mb-12">
                                <div>
                                    <h2 className="text-white text-2xl md:text-4xl font-black uppercase tracking-tight">Full Intelligence Briefing</h2>
                                    <p className="text-indigo-400 text-xs mt-2 uppercase tracking-[0.3em] font-bold">Strategy: {intelligenceMode || 'Standard'}</p>
                                </div>
                                <button onClick={() => setIsFullReportOpen(false)} className="text-white/60 hover:text-white transition-colors"><FiX size={34} /></button>
                            </div>
                            <div className="space-y-12">
                                <Section label="Executive Summary" text={aiInsights.summary} />
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div className="p-6 bg-white/5 border border-white/10 rounded-2xl">
                                        <h4 className="text-emerald-400 text-[10px] font-black uppercase tracking-widest mb-2">ROI Impact</h4>
                                        <p className="text-white text-xl font-bold">{aiInsights.roi_impact || "High Strategic Yield"}</p>
                                    </div>
                                    <div className="p-6 bg-white/5 border border-white/10 rounded-2xl">
                                        <h4 className="text-indigo-400 text-[10px] font-black uppercase tracking-widest mb-2">Confidence Level</h4>
                                        <p className="text-white text-xl font-bold">{aiInsights.confidence || "94.2% Neural Match"}</p>
                                    </div>
                                </div>
                                <Section label="Primary Root Cause" text={aiInsights.root_cause} />
                                <Section label="Risk Exposure" text={aiInsights.risk} />
                                <Section label="Opportunity" text={aiInsights.opportunity} />
                                <Section label="Recommended Action" text={aiInsights.action} />
                            </div>
                            <div className="flex justify-end mt-12 gap-6 pb-20">
                                <button onClick={() => toggleSpeech()} className="flex items-center gap-3 px-10 py-4 bg-indigo-500 text-white rounded-xl text-[13px] font-black uppercase tracking-widest hover:bg-white hover:text-black transition-all">
                                    <FaVolumeUp /> {isSpeaking ? "Stop Briefing" : "Read Out Loud"}
                                </button>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

const Section = ({ label, text }) => (
    <div className="border-l-2 border-indigo-500/20 pl-8">
        <h3 className="text-indigo-400 text-[12px] uppercase tracking-[0.5em] font-black mb-3">{label}</h3>
        <p className="text-white text-xl leading-relaxed font-light">{text}</p>
    </div>
);

export default AIAnalysisPanel;