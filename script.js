const scenarios = [
  {
    id: 1,
    type: "Email",
    difficulty: "Beginner",
    sender: "IT Support <security-update@company-it-helpdesk.net>",
    subject: "Urgent: Confirm your password reset today",
    content:
      "Hello,\n\nOur records show suspicious login attempts on your account. To avoid account suspension, confirm your password reset immediately using the secure employee portal below:\nhttp://company-verify-login.net/reset\n\nFailure to act within 30 minutes will result in mailbox deactivation.\n\nIT Support",
    isPhishing: true,
    redFlags: [
      "The sender domain is unrelated to the real company domain.",
      "The message pressures the user with an unusually short deadline.",
      "The link uses plain HTTP and points to a suspicious external site."
    ],
    explanation:
      "This message uses urgency and a fake support identity to push a rushed click. Real IT teams usually direct users to known internal portals rather than unfamiliar external links.",
    categories: ["sender verification", "urgency", "link inspection"]
  },
  {
    id: 2,
    type: "Email",
    difficulty: "Beginner",
    sender: "HR Team <benefits@company.com>",
    subject: "Open enrollment schedule for next week",
    content:
      "Hi team,\n\nOpen enrollment starts next Monday. You can review plan details on the employee portal or join the Q&A session on Wednesday at 2:00 PM.\n\nBenefits portal: https://benefits.company.com\nCalendar invite attached in the official HR calendar.\n\nBest,\nHR Team",
    isPhishing: false,
    redFlags: [
      "No major red flags in this scenario.",
      "The sender uses the expected company domain.",
      "The message refers users to a familiar HTTPS company portal."
    ],
    explanation:
      "This is a legitimate internal notice. The tone is informational, the domain matches the organization, and there is no coercive pressure to bypass normal process.",
    categories: ["sender verification", "link inspection"]
  },
  {
    id: 3,
    type: "SMS",
    difficulty: "Intermediate",
    sender: "ParcelAlerts",
    subject: "Delivery text",
    content:
      "Package pending: your delivery could not be completed. Confirm address now to avoid return fees: https://track-myparcel-fast.com/resolve",
    isPhishing: true,
    redFlags: [
      "The message creates financial pressure with a vague penalty.",
      "The link uses a generic lookalike domain instead of a major carrier.",
      "There is no shipment number or verifying detail tied to a real order."
    ],
    explanation:
      "Phishing texts often exploit everyday tasks like package delivery. When the message lacks details you can independently confirm and pushes an unfamiliar link, it should be treated with caution.",
    categories: ["urgency", "link inspection", "context validation"]
  },
  {
    id: 4,
    type: "Email",
    difficulty: "Intermediate",
    sender: "Finance Ops <finance@company.co>",
    subject: "Updated invoice for April vendor payment",
    content:
      "Please process the attached invoice before 5 PM so we can avoid service interruption. The vendor changed their bank information this morning, so use the new routing details in the spreadsheet attachment.\n\nThanks,\nFinance Ops",
    isPhishing: true,
    redFlags: [
      "The sender uses a lookalike domain that is close to the company's real one.",
      "It requests a high-risk financial action with same-day urgency.",
      "Bank detail changes should be verified out-of-band before payment."
    ],
    explanation:
      "Business email compromise often impersonates finance or vendors and pushes urgent payment changes. High-risk requests need verification through a trusted channel, even when the email looks plausible.",
    categories: ["sender verification", "urgency", "process awareness"]
  },
  {
    id: 5,
    type: "Email",
    difficulty: "Advanced",
    sender: "Google Workspace <no-reply@accounts.google.com>",
    subject: "New sign-in from Chrome on Windows",
    content:
      "We noticed a new sign-in to your account from Chrome on Windows. If this was you, no action is needed.\n\nReview activity: https://accounts.google.com/signin/activity\n\nYou can also manage alerts in your account security settings.",
    isPhishing: false,
    redFlags: [
      "No obvious red flags are present here.",
      "The domain matches an expected Google security notification sender.",
      "The message suggests review rather than coercing immediate panic."
    ],
    explanation:
      "Legitimate security notices can look urgent, which is why context matters. The sender and link destination are consistent with a real provider, and the message does not push an unusual workflow.",
    categories: ["sender verification", "link inspection", "context validation"]
  },
  {
    id: 6,
    type: "Email",
    difficulty: "Advanced",
    sender: "CEO Office <assistant.exec@company.com>",
    subject: "Need gift cards for client appreciation today",
    content:
      "I'm stepping into meetings all afternoon and need your help right away. Please buy six $100 gift cards and send the codes back by email before 3 PM. Keep this between us until I announce the initiative.\n\nSent from my phone",
    isPhishing: true,
    redFlags: [
      "The request asks for gift cards, a common social engineering tactic.",
      "It uses secrecy and urgency to discourage verification.",
      "The action bypasses normal purchasing and approval processes."
    ],
    explanation:
      "Executive impersonation scams rely on authority pressure. Even when the sender address appears familiar, unusual requests involving money, secrecy, or policy bypasses should be verified through another channel.",
    categories: ["urgency", "process awareness", "authority pressure"]
  }
];

const state = {
  index: 0,
  correct: 0,
  answered: 0,
  missesByCategory: {}
};

const elements = {
  scenarioType: document.getElementById("scenario-type"),
  difficulty: document.getElementById("scenario-difficulty"),
  sender: document.getElementById("sender"),
  subject: document.getElementById("subject"),
  content: document.getElementById("content"),
  safeButton: document.getElementById("safe-button"),
  phishingButton: document.getElementById("phishing-button"),
  feedback: document.getElementById("feedback"),
  feedbackHeading: document.getElementById("feedback-heading"),
  feedbackCopy: document.getElementById("feedback-copy"),
  redFlags: document.getElementById("red-flags"),
  nextButton: document.getElementById("next-button"),
  progressCount: document.getElementById("progress-count"),
  correctCount: document.getElementById("correct-count"),
  accuracyRate: document.getElementById("accuracy-rate"),
  weaknessList: document.getElementById("weakness-list"),
  summaryPanel: document.getElementById("summary-panel"),
  summaryText: document.getElementById("summary-text"),
  restartButton: document.getElementById("restart-button")
};

function renderScenario() {
  const scenario = scenarios[state.index];

  elements.scenarioType.textContent = scenario.type;
  elements.difficulty.textContent = scenario.difficulty;
  elements.sender.textContent = scenario.sender;
  elements.subject.textContent = scenario.subject;
  elements.content.textContent = scenario.content;
  elements.progressCount.textContent = `${state.index + 1} / ${scenarios.length}`;
  elements.feedback.className = "feedback hidden";
  elements.redFlags.innerHTML = "";
  elements.safeButton.disabled = false;
  elements.phishingButton.disabled = false;
}

function updateScoreboard() {
  const accuracy = state.answered === 0 ? 0 : Math.round((state.correct / state.answered) * 100);
  elements.correctCount.textContent = String(state.correct);
  elements.accuracyRate.textContent = `${accuracy}%`;

  const sortedWeaknesses = Object.entries(state.missesByCategory)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 4);

  if (sortedWeaknesses.length === 0) {
    elements.weaknessList.innerHTML = `
      <div class="weakness-item">
        <strong>No missed categories yet</strong>
        <p>Your learning gaps will appear here when you miss a scenario.</p>
      </div>
    `;
    return;
  }

  elements.weaknessList.innerHTML = sortedWeaknesses
    .map(([category, count]) => `
      <div class="weakness-item">
        <strong>${toTitleCase(category)}</strong>
        <p>Missed in ${count} scenario${count === 1 ? "" : "s"}.</p>
      </div>
    `)
    .join("");
}

function submitAnswer(markedPhishing) {
  const scenario = scenarios[state.index];
  const isCorrect = scenario.isPhishing === markedPhishing;

  state.answered += 1;
  if (isCorrect) {
    state.correct += 1;
  } else {
    scenario.categories.forEach((category) => {
      state.missesByCategory[category] = (state.missesByCategory[category] || 0) + 1;
    });
  }

  elements.feedback.className = `feedback ${scenario.isPhishing ? "phishing-result" : "safe-result"}`;
  elements.feedbackHeading.textContent = isCorrect
    ? "Correct decision"
    : `Not quite: this was ${scenario.isPhishing ? "phishing" : "legitimate"}`;
  elements.feedbackCopy.textContent = scenario.explanation;
  elements.redFlags.innerHTML = scenario.redFlags.map((flag) => `<li>${flag}</li>`).join("");
  elements.safeButton.disabled = true;
  elements.phishingButton.disabled = true;

  updateScoreboard();
}

function showSummary() {
  const accuracy = Math.round((state.correct / scenarios.length) * 100);
  const strengths =
    accuracy >= 80
      ? "Strong work. You are making careful trust decisions instead of reacting to pressure."
      : "You are building the right instincts. Another round will help reinforce the trickier patterns.";

  elements.summaryText.textContent = `${strengths} You finished ${scenarios.length} scenarios with ${accuracy}% accuracy.`;
  elements.summaryPanel.classList.remove("hidden");
}

function nextScenario() {
  state.index += 1;
  if (state.index >= scenarios.length) {
    elements.feedback.classList.add("hidden");
    elements.safeButton.disabled = true;
    elements.phishingButton.disabled = true;
    elements.progressCount.textContent = `${scenarios.length} / ${scenarios.length}`;
    showSummary();
    return;
  }

  renderScenario();
}

function restartRound() {
  state.index = 0;
  state.correct = 0;
  state.answered = 0;
  state.missesByCategory = {};
  elements.summaryPanel.classList.add("hidden");
  updateScoreboard();
  renderScenario();
}

function toTitleCase(value) {
  return value.replace(/\b\w/g, (char) => char.toUpperCase());
}

elements.safeButton.addEventListener("click", () => submitAnswer(false));
elements.phishingButton.addEventListener("click", () => submitAnswer(true));
elements.nextButton.addEventListener("click", nextScenario);
elements.restartButton.addEventListener("click", restartRound);

updateScoreboard();
renderScenario();
