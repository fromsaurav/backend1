import mongoose from "mongoose";

const candidateSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  votes: {
    type: Number,
    required: true,
    default: 0,
    min: 0,
  },
}, { timestamps: true });

candidateSchema.statics.addCandidate = async function (name) {
  try {
    const candidate = new this({ name });
    await candidate.save();
    return candidate;
  } catch (error) {
    throw new Error(`Error adding candidate: ${error.message}`);
  }
};

candidateSchema.statics.removeCandidate = async function (id) {
  try {
    const candidate = await this.findByIdAndDelete(id);
    if (!candidate) {
      throw new Error('Candidate not found');
    }
    return candidate;
  } catch (error) {
    throw new Error(`Error removing candidate: ${error.message}`);
  }
};

export const Candidate = mongoose.model('Candidate', candidateSchema);

