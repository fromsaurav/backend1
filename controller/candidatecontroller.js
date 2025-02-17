import {Candidate} from "../models/candidateSchema.js";

// Add a candidate
export const addCandidate = async (name) => {
  try {
    const candidate = new Candidate({ name }); // Create a new candidate
    await candidate.save(); // Save to the database
    return { success: true, candidate };
  } catch (error) {
    return { success: false, message: error.message };
  }
};

// Remove a candidate
export const removeCandidate = async (id) => {
  try {
    const candidate = await Candidate.findByIdAndDelete(id); // Find and delete candidate
    if (!candidate) {
      throw new Error("Candidate not found");
    }
    return { success: true, candidate };
  } catch (error) {
    return { success: false, message: error.message };
  }
};

// Add votes to a candidate
export const addVote = async (id, voteCount = 1) => {
  try {
    const candidate = await Candidate.findById(id); // Find the candidate
    if (!candidate) {
      throw new Error("Candidate not found");
    }
    candidate.votes += voteCount; // Increment votes
    await candidate.save(); // Save updated candidate
    return { success: true, candidate };
  } catch (error) {
    return { success: false, message: error.message };
  }
};

export const getAllCandidates = async () => {
    try {
      const candidates = await Candidate.find(); // Fetch all candidates
      return { success: true, candidates };
    } catch (error) {
      return { success: false, message: error.message };
    }
  };
  import { JobApplication } from "../models/jobApplicationSchema.js";

export const checkVoteStatus = async (req, res) => {
  const { identifier } = req.query; // Identifier can be reg, email, or any unique field

  if (!identifier) {
    return res.status(400).json({ message: "Identifier is required!" });
  }

  try {
    // Find the student using the identifier
    const student = await JobApplication.findOne({
      $or: [{ reg: identifier }, { email: identifier }],
    });

    if (!student) {
      return res.status(404).json({ message: "Student not found!" });
    }

    // Return the voting status
    return res.status(200).json({
      identifier,
      hasVoted: student.isVoted,
    });
  } catch (error) {
    console.error("Error checking vote status:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};
export const updateVotingStatus = async (req, res) => {
    const { identifier } = req.body;
  
    if (!identifier) {
      return res.status(400).json({ success: false, message: "Identifier is required!" });
    }
  
    try {
      const student = await JobApplication.findOne({
        $or: [{ reg: identifier }, { email: identifier }],
      });
  
      if (!student) {
        return res.status(404).json({ success: false, message: "Student not found!" });
      }
  
      student.isVoted = true; // Update the voting status
      await student.save();
  
      res.status(200).json({ success: true, message: "Voting status updated successfully!" });
    } catch (error) {
      console.error("Error updating voting status:", error.message);
      res.status(500).json({ success: false, message: "Internal server error." });
    }
  };

