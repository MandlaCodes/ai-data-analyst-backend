import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bodyParser from "body-parser";

// --- MongoDB Setup ---
mongoose.connect("mongodb+srv://<username>:<password>@cluster0.mongodb.net/adt_dashboards?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => console.log("MongoDB connected"));

// --- Dashboard Schema ---
const dashboardSchema = new mongoose.Schema({
  user_id: { type: String, required: true },
  layout_data: { type: String, required: true }, // JSON string of dashboard
  is_current: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

const Dashboard = mongoose.model("Dashboard", dashboardSchema);

// --- Express App ---
const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- Routes ---

// Save or update dashboard for a user
app.post("/api/dashboard/save", async (req, res) => {
  try {
    const { user_id, layout_data } = req.body;

    if (!user_id || !layout_data) {
      return res.status(400).json({ message: "Missing user_id or layout_data" });
    }

    // Set previous dashboards to not current
    await Dashboard.updateMany({ user_id }, { is_current: false });

    // Save new dashboard
    const dashboard = new Dashboard({ user_id, layout_data, is_current: true });
    await dashboard.save();

    res.json({ message: "Dashboard saved successfully", dashboard });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Fetch dashboards for a user
app.get("/api/dashboard/sessions", async (req, res) => {
  try {
    const { user_id } = req.query;
    if (!user_id) return res.status(400).json({ message: "Missing user_id" });

    const sessions = await Dashboard.find({ user_id }).sort({ createdAt: -1 });
    res.json({ sessions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
