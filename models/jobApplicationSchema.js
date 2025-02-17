import mongoose from "mongoose";
import validator from "validator";
import jwt from "jsonwebtoken";

// Schema for verification status
const verificationStatusSchema = new mongoose.Schema({
  isVerified: {
    type: Boolean,
    default: false,
  },
  verifiedBy: {
    type: String,
    default: null,
  },
  verifiedAt: {
    type: Date,
    default: null,
  }
}, { _id: false });

// Schema for proofs
const proofSchema = new mongoose.Schema({
  url: {
    type: String,
    // required: [true, "Proof URL is required!"]
  },
  public_id: {
    type: String,
    // required: [true, "Proof Public ID is required!"]
  },
  verification: {
    type: verificationStatusSchema,
    default: () => ({})
  }
}, { _id: false });

const jobApplicationSchema = new mongoose.Schema({
  reg: {
    type: String,
    required: [true, "Registration Number is Required!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  fullName: {
    type: String,
    required: [true, "Full Name is Required!"],
    minLength: [3, "Full Name Must Contain At Least 3 Characters!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  email: {
  type: String,
  required: [true, "Email is Required!"],
  unique: true, // Ensure that email is unique
  validate: [validator.isEmail, "Provide A Valid Email!"],
  verification: {
    type: verificationStatusSchema,
    default: () => ({})
  }
},
  phone: {
    type: String,
    required: [true, "Phone is Required!"],
    minLength: [9, "Phone Number Must Contain At Least 10 Digits!"],
    maxLength: [15, "Phone Number Must Contain No More Than 15 Digits!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  cgpa: {
    type: Number,
    required: [true, "CGPA is Required!"],
    min: [0, "CGPA Must Be At Least 0!"],
    max: [10, "CGPA Must Be At Most 10!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  cgpaProof: {
    type: proofSchema,
    required: [true, "CGPA Proof is Required!"],
  },
  dob: {
    type: Date,
    required: [true, "Date of Birth is Required!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  gender: {
    type: String,
    required: [true, "Gender is Required!"],
    enum: ["Male", "Female", "Other"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  ssc: {
    type: Number,
    required: [true, "SSC Percentage is Required!"],
    min: [0, "SSC Percentage Must Be At Least 0!"],
    max: [100, "SSC Percentage Must Be At Most 100!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  sscProof: {
    type: proofSchema,
    required: [true, "SSC Proof is Required!"],
  },
  hsc: {
    type: Number,
    required: [true, "HSC/Diploma Percentage is Required!"],
    min: [0, "HSC/Diploma Percentage Must Be At Least 0!"],
    max: [100, "HSC/Diploma Percentage Must Be At Most 100!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  hscProof: {
    type: proofSchema,
    required: [true, "HSC Proof is Required!"],
  },
  profilePhotoProof: {
    type: proofSchema,
    required: [true, "ProfilePhoto Proof is Required!"],
  },
  gap_year: {
    type: Number,
    required: [true, "Gap year is Required! / if No Gap Year Type NA"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  backlogs: {
    type: Number,
    required: [true, "backlogs is Required!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  gap_yearProof: {
    type: proofSchema,
    // required: [ "Gap Year Proof is Required!"],
  },
  projects: {
    type: String,
    required: [true, "Projects are Required!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  internship: {
    type: String,
    required: [true, "Internship Details are Required! If not Done InternShip Type NA"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  internshipProof: {
    type: proofSchema,
    // required: [true, "Internship Proof is Required!"],
  },
  branch: {
    type: String,
    required: [true, "Branch is Required!"],
    enum: ["EXTC", "Mech", "CSE", "Civil", "Elect","IT","Text","Chem","INST","Prod"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  address: {
    type: String,
    required: [true, "Address is Required!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  skills: {
    type: String,
    required: [true, "Skills are Required!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  references: {
    type: String,
    required: [true, "References are Required!"],
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  placed: {
    type: String,
    enum: ["Placed", "Not Placed"],
    default: "Not Placed",
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  isVoted: {
    type: Boolean,
    default: false
    
    
  },
  amount: {
    type: Number,
    min: [0, "Package must be a positive number!"],
    default: 0,
    verification: {
      type: verificationStatusSchema,
      default: () => ({})
    }
  },
  status: {
    type: String,
    enum: ["Pending", "Accepted", "Rejected"],
    default: "Pending",
  },
  message: {
    type: String,
   
    
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});
jobApplicationSchema.methods.generateJsonWebToken = function () {
  return jwt.sign({ id: this._id, email: this.email }, process.env.JWT_SECRET_KEY, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

export const JobApplication = mongoose.model("JobApplication", jobApplicationSchema);
