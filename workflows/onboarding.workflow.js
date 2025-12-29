// workflows/onboarding.workflow.js
// AI-guided business onboarding (Advanced plan)
//
// Responsibilities:
// - Ask structured onboarding questions
// - Maintain session state
// - Build business profile for AI + escalation + reports
//
// Does NOT:
// - Handle HTTP
// - Call OpenAI directly (can be added later)

const crypto = require("crypto");

// In-memory session store (safe for MVP / SMB)
// Can be replaced with DB later without rework
const sessions = new Map();

// -------------------------------
// Question flow definition
// -------------------------------
const QUESTIONS = [
  {
    key: "business_name",
    question: "What is your business name?"
  },
  {
    key: "industry",
    question: "What industry do you operate in? (e.g., retail, services, SaaS)"
  },
  {
    key: "primary_goal",
    question: "What should the AI help you with most? (sales, support, bookings, FAQs)"
  },
  {
    key: "customer_channels",
    question: "Where do your customers contact you most? (website, WhatsApp, Instagram)"
  },
  {
    key: "business_hours",
    question: "What are your business working hours?"
  },
  {
    key: "owner_email",
    question: "What email should receive escalations and reports?"
  },
  {
    key: "knowledge_sources",
    question:
      "Share any website links, documents, or notes the AI should learn from (you can paste URLs or text)."
  }
];

// -------------------------------
// Helpers
// -------------------------------
function createSessionId() {
  return crypto.randomBytes(12).toString("hex");
}

function getNextQuestion(session) {
  if (session.step >= QUESTIONS.length) return null;
  return QUESTIONS[session.step];
}

// -------------------------------
// Public APIs
// -------------------------------

/**
 * Start onboarding
 */
async function startOnboarding({ site, ownerEmail }) {
  const sessionId = createSessionId();

  sessions.set(sessionId, {
    sessionId,
    site,
    ownerEmail: ownerEmail || null,
    step: 0,
    answers: {},
    startedAt: new Date().toISOString()
  });

  const firstQuestion = QUESTIONS[0];

  return {
    sessionId,
    message:
      "Welcome 👋 Let’s set up your AI assistant.\n\n" +
      firstQuestion.question
  };
}

/**
 * Handle onboarding message
 */
async function handleMessage({ sessionId, message }) {
  const session = sessions.get(sessionId);
  if (!session) {
    throw new Error("Invalid onboarding session");
  }

  const currentQuestion = QUESTIONS[session.step];
  if (!currentQuestion) {
    return {
      completed: true,
      message: "Onboarding already completed."
    };
  }

  // Save answer
  session.answers[currentQuestion.key] = message;
  session.step += 1;

  const nextQuestion = getNextQuestion(session);

  if (!nextQuestion) {
    return {
      completed: true,
      message:
        "✅ Thanks! I’ve collected everything needed.\n\n" +
        "You can now integrate the AI on your website or WhatsApp."
    };
  }

  return {
    completed: false,
    message: nextQuestion.question
  };
}

/**
 * Complete onboarding and return business profile
 */
async function completeOnboarding({ sessionId }) {
  const session = sessions.get(sessionId);
  if (!session) {
    throw new Error("Invalid onboarding session");
  }

  const profile = {
    site: session.site,
    ownerEmail:
      session.answers.owner_email || session.ownerEmail || null,
    businessName: session.answers.business_name || null,
    industry: session.answers.industry || null,
    primaryGoal: session.answers.primary_goal || null,
    channels: session.answers.customer_channels || null,
    businessHours: session.answers.business_hours || null,
    knowledgeSources: session.answers.knowledge_sources || null,
    createdAt: new Date().toISOString()
  };

  // Cleanup session (important)
  sessions.delete(sessionId);

  return {
    completed: true,
    profile,
    message:
      "🎉 Your AI assistant is configured!\n\n" +
      "Next steps:\n" +
      "• Embed on website\n" +
      "• Connect WhatsApp\n" +
      "• Start receiving reports"
  };
}

// -------------------------------
// Export
// -------------------------------
module.exports = {
  startOnboarding,
  handleMessage,
  completeOnboarding
};

