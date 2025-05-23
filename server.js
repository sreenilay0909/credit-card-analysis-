const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const fs = require('fs');
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');
const csv = require('csvtojson');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode'); // Ensure this is at the top
const pdf = require('html-pdf'); // For HTML to PDF conversion for email reports

const app = express();

// Assuming User model is defined in models/User.js
const User = require('./models/User');

const port = 3019; // Define the port for your server

// --- MongoDB connection ---
mongoose.connect('mongodb://127.0.0.1:27017/students', {
    useNewUrlParser: true, // Deprecated, but harmless for now
    useUnifiedTopology: true, // Deprecated, but harmless for now
});
mongoose.connection.once('open', () => console.log("MongoDB connected."));

// --- IMPORTANT: Centralized Body Parser Middleware with Increased Limits ---
// This should be placed early in your middleware chain to apply to all incoming requests.
// It replaces multiple instances of bodyParser.urlencoded and express.json/urlencoded.
app.use(express.json({ limit: '50mb' })); // Increased limit for JSON payloads (for credit card analyzer report)
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Increased limit for URL-encoded payloads

// --- Serve Static Files ---
// Serve files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));
// Serve files from the root directory (e.g., apply_credit.html if it's directly in 'project')
app.use(express.static(__dirname));

// --- Session Middleware ---
app.use(session({
    secret: 'secretkey', // Replace with a strong, unique secret in production
    resave: false,
    saveUninitialized: false
}));


// --- Load CSV data once when the server starts ---
let dataset = [];
csv()
  .fromFile('creditcard_data.csv') // Ensure this file exists in your project root
  .then((jsonObj) => {
    dataset = jsonObj.map(entry => ({
      name: entry.name.trim().toLowerCase(),
      card_number: entry["Card Number"].trim(),
      security_code: entry["Security Code"].trim(),
      phone_number: entry["phone_number"].trim()
    }));
    console.log("CSV loaded with", dataset.length, "records");
  })
  .catch(err => {
    console.error("Failed to load creditcard_data.csv:", err);
    // Exit process or handle gracefully if critical for app
  });

// --- Multer setup for file uploads ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });

// --- Mongoose Schemas ---
const creditSchema = new mongoose.Schema({
    fullname: String, father_name: String, mother_name: String, dob: Date, gender: String, mobile: Number, email: String, bank: String, address: String, city: String, state: String, pin: Number, nationality: String, employment: String, monthly_income: String, annual_income: String, employer: String, occupation: String, account: String, pan: String, aadhar: String, cardType: String, nominee_name: String, nominee_relation: String, nominee_dob: Date, credit_score: String,
    files: { userPhoto: String, userSignature: String, idProof: String, addressProof: String, incomeProof: String }
});

const debitSchema = new mongoose.Schema({
    first_name: String, middle_name: String, last_name: String, dob: Date, phone: Number, email: String, bank: String, gender: String, state: String, city: String, pin: Number, street: String, address: String, aadhar_number: String, pan_number: String, account_type: String, debit_card_type: String,
    files: { userPhoto: String, userSignature: String }
});

const contactSchema = new mongoose.Schema({
    name: String, email: String, subject: String, message: String
});

const CreditModel = mongoose.model("CreditData", creditSchema);
const DebitModel = mongoose.model("DebitData", debitSchema);
const ContactModel = mongoose.model("ContactData", contactSchema);

// --- PDF Generator Function (using pdfkit) ---
async function generatePDF(data, filePath, images = {}) {
    return new Promise(async (resolve) => {
        const doc = new PDFDocument({ margin: 40 });
        doc.pipe(fs.createWriteStream(filePath));

        // Add Logo at the top center
        const logoPath = path.join(__dirname, 'assets', 'logo.png'); // Ensure you have an 'assets' folder with 'logo.png'
        if (fs.existsSync(logoPath)) {
            doc.image(logoPath, doc.page.width / 2 - 50, 20, { width: 100 });
            doc.moveDown(3);
        }

        // Title
        doc.fontSize(18).text("Form Submission", { align: 'center' }).moveDown(2);

        // Helper to render a section
        const renderSection = (title, fields) => {
            doc.fontSize(14).fillColor('blue').text(title, { underline: true }).moveDown(0.5);
            doc.fontSize(11).fillColor('black');
            fields.forEach(key => {
                // Check if the key exists in data and is not null/undefined
                if (data[key] !== undefined && data[key] !== null) {
                    let displayValue = data[key];
                    // Handle Date objects for display
                    if (data[key] instanceof Date) {
                        displayValue = data[key].toLocaleDateString();
                    }
                    doc.text(`${key.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase())}: ${displayValue}`);
                }
            });
            doc.moveDown(1);
        };

        // Grouped sections (adjust field names as per your form data)
        renderSection("Personal Information", [
            'fullname', 'first_name', 'middle_name', 'last_name', 'dob', 'gender', 'nationality', 'pan', 'aadhar', 'aadhar_number', 'occupation'
        ]);

        renderSection("Contact Information", [
            'email', 'mobile', 'phone', 'address', 'city', 'state', 'pin', 'street'
        ]);

        renderSection("Bank & Employment Details", [
            'bank', 'account', 'account_type', 'employment', 'monthly_income', 'annual_income', 'employer'
        ]);

        renderSection("Card & Nominee Info", [
            'cardType', 'debit_card_type', 'nominee_name', 'nominee_relation', 'nominee_dob', 'credit_score'
        ]);

        renderSection("Contact Form Message", ['subject', 'message']);

        // Add uploaded images
        if (images.userPhoto && fs.existsSync(images.userPhoto)) {
            doc.addPage().fontSize(14).text("Uploaded Photo:").image(images.userPhoto, { fit: [250, 250] });
        }

        if (images.userSignature && fs.existsSync(images.userSignature)) {
            doc.addPage().fontSize(14).text("Uploaded Signature:").image(images.userSignature, { fit: [250, 250] });
        }

        // Optional: generate a QR code with summary info
        const qrData = `Submitted by: ${data.fullname || data.first_name || 'Unknown'}\nEmail: ${data.email || 'N/A'}`;
        const qrCodeBuffer = await QRCode.toBuffer(qrData);
        doc.addPage().fontSize(14).text("QR Code Summary:").image(qrCodeBuffer, { fit: [150, 150] });

        doc.end();
        resolve();
    });
}

// --- Nodemailer Transporters ---
// IMPORTANT: Replace 'sreenilay0909@gmail.com' and 'keoypyainkaxvnpl' with your actual Gmail address and generated App Password.
// For security, it's highly recommended to use environment variables for these credentials in a production environment.

// Transporter for login/forgot password emails
const loginTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: '', // Your Gmail address
        pass: ''   // Your Gmail App Password
    }
});

// Transporter for credit card analyzer report emails
const analyzerTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: '', // Your Gmail address
        pass: ''   // Your Gmail App Password
    }
});

// Transporter for general form submission emails (emailPDF function)
const formTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: '', // Your Gmail address
        pass: ''   // Your Gmail App Password
    }
});

// --- Routes for Login/Registration ---
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot-password.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));
app.get('/main.html', (req, res) => { // Assuming this is the dashboard after login
    if (!req.session.userId) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }
    res.sendFile(path.join(__dirname, 'public', 'main.html'));
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).send('All fields are required.');
    }
    try {
        const hashed = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashed });
        await newUser.save();
        res.status(201).send('User registered. <a href="/login">Login</a>');
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).send('Error registering user. Please try again.');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Email and password are required.');
    }
    try {
        const user = await User.findOne({ email });
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user._id;
            res.redirect('/main.html');
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).send('An error occurred during login.');
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).send('Email is required.');
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).send('No user with this email found.');

        const tempPass = Math.random().toString(36).slice(-8);
        const hashedTemp = await bcrypt.hash(tempPass, 10);
        user.tempPassword = hashedTemp;
        await user.save();

        await loginTransporter.sendMail({
            from: '"Your Card System" <sreenilay0909@gmail.com>',
            to: email,
            subject: 'Temporary Password for Reset',
            text: `Hello,

We received a request to reset your password. Please use the temporary password below to proceed:

Temporary Password: ${tempPass}

For security reasons, we recommend that you reset your password as soon as possible.

If you did not request a password reset, please ignore this email.

Best regards,
Your Card System Support Team`
        });
        res.send('A temporary password has been sent to your registered email address. Please check your inbox (and spam folder). <br><br><a href="/reset-password">Click here to reset your password</a>');
    } catch (error) {
        console.error("Error sending forgot password email:", error);
        res.status(500).send('Failed to send temporary password email. Please try again later.');
    }
});

app.post('/reset-password', async (req, res) => {
    const { email, tempPassword, newPassword } = req.body;
    if (!email || !tempPassword || !newPassword) {
        return res.status(400).send('All fields are required.');
    }
    try {
        const user = await User.findOne({ email });
        if (!user || !user.tempPassword || !await bcrypt.compare(tempPassword, user.tempPassword)) {
            return res.status(401).send('Invalid temporary password or email.');
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.tempPassword = undefined; // Clear the temporary password
        await user.save();
        res.send('Password reset successfully. <a href="/login">Login</a>');
    } catch (error) {
        console.error("Reset password error:", error);
        res.status(500).send('An error occurred during password reset.');
    }
});


// --- Credit Card Analyzer Routes ---
// Access this page via http://localhost:3019/credit-card-analyzer
app.get('/credit-card-analyzer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'credit_card_analyzer.html'));
});

// API endpoint to send the report via email
app.post('/api/send-report-email', (req, res) => {
    const { email, reportHtmlContent } = req.body;

    if (!email || !reportHtmlContent) {
        return res.status(400).json({ error: 'Recipient email and report content are required.' });
    }

    const pdfOptions = {
        format: 'A4', orientation: 'portrait', border: '10mm',
        header: { height: '15mm', contents: '<div style="text-align: center; font-size: 10px; color: #555;">Credit Card Transaction Analysis Report</div>' },
        footer: { height: '10mm', contents: { first: '<div style="text-align: center; font-size: 9px; color: #888;">Page {{page}} of {{pages}}</div>', default: '<div style="text-align: center; font-size: 9px; color: #888;">Page {{page}} of {{pages}}</div>' } }
    };

    // Generate PDF from HTML content
    pdf.create(reportHtmlContent, pdfOptions).toBuffer((err, buffer) => {
        if (err) {
            console.error('PDF generation error:', err);
            return res.status(500).json({ error: 'Failed to generate PDF report.', details: err.message });
        }

        const mailOptions = {
            from: '"Your Card System" <sreenilay0909@gmail.com>',
            to: email,
            subject: 'Credit Card Transaction Analysis Report',
            text:`Dear User,

Please find attached your comprehensive Credit Card Transaction Analysis Report.

This report provides detailed insights into your spending patterns and highlights any potential fraudulent activities detected.

If you have any questions or require further assistance, please do not hesitate to reply to this email.


If you notice any incorrect or missing information, please reply to this email immediately.

Warm regards,
Your Card System Team
For any queries, please contact us at: sreenilay99@gmail.com


[Nilay, Abinay/Your Card Analyzer Team]
Your Card Analyzer Team

            `,
            attachments: [
                {
                    filename: 'credit_card_report.pdf',
                    content: buffer,
                    contentType: 'application/pdf'
                }
            ]
        };

        // Send the email with detailed error logging
        analyzerTransporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending analyzer email:', error); // More specific log
                return res.status(500).json({ error: 'Failed to send email.', details: error.message });
            }
            console.log('Analyzer email sent: ' + info.response);
            res.status(200).json({ message: 'Report sent successfully!' });
        });
    });
});

// --- Email PDF Function (for other forms, uses formTransporter) ---
async function emailPDF(to, filePath) {
    try {
        await formTransporter.sendMail({
            from: '"Your Card System" <sreenilay0909@gmail.com>',
            to,
            subject: "Your Form Submission PDF",
            text: `Dear User,

Thank you for submitting your form to our system.

We appreciate your time and effort in providing your details. As part of our verification and transparency process, we have generated a PDF document that contains all the information you submitted to us via the application form.

The PDF file is attached to this email. We kindly ask you to review the contents of the attached file carefully.

Please verify the following:

- Your full name
- Date of birth
- Contact details (email, phone number)
- Address
- Identity and address proof information
- Uploaded documents (if any)

If you notice any incorrect or missing information, please reply to this email immediately.

Warm regards,
Your Card System Team
For any queries, please contact us at: sreenilay99@gmail.com`,
            attachments: [{
                filename: path.basename(filePath),
                path: filePath
            }]
        });
    } catch (error) {
        console.error("Error sending form submission email:", error);
    }
}

// --- Routes for Verification ---
// Access this page via http://localhost:3019/verify
app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify_details.html'));
});

app.post('/verify', (req, res) => {
  const { name, card_number, security_code, phone_number } = req.body;
  const match = dataset.find(entry =>
    entry.name === name.trim().toLowerCase() &&
    entry.card_number === card_number.trim() &&
    entry.security_code === security_code.trim() &&
    entry.phone_number === phone_number.trim()
  );
  if (match) {
    res.sendFile(path.join(__dirname, 'public', 'verify_success.html'));
  } else {
    res.redirect('/verify?error=1'); // Redirect to /verify with error
  }
});


// --- Routes for Form Submissions ---
app.post('/submitCreditForm', upload.fields([
    { name: 'userPhoto' }, { name: 'userSignature' }, { name: 'idProof' }, { name: 'addressProof' }, { name: 'incomeProof' }
]), async (req, res) => {
    const files = req.files;
    const body = req.body;

    try {
        const newData = new CreditModel({
            ...body,
            dob: body.dob ? new Date(body.dob) : null, // Handle potential missing date
            nominee_dob: body.nominee_dob ? new Date(body.nominee_dob) : null,
            mobile: body.mobile ? Number(body.mobile) : null,
            pin: body.pin ? Number(body.pin) : null,
            files: {
                userPhoto: files.userPhoto?.[0]?.path,
                userSignature: files.userSignature?.[0]?.path,
                idProof: files.idProof?.[0]?.path,
                addressProof: files.addressProof?.[0]?.path,
                incomeProof: files.incomeProof?.[0]?.path
            }
        });
        await newData.save();

        const pdfPath = `uploads/credit_${Date.now()}.pdf`;
        await generatePDF(body, pdfPath, {
            userPhoto: files.userPhoto?.[0]?.path,
            userSignature: files.userSignature?.[0]?.path
        });
        await emailPDF(body.email, pdfPath); // Use the general emailPDF function

        res.redirect('/success.html'); // Ensure success.html exists
    } catch (error) {
        console.error("Error submitting credit form:", error);
        res.status(500).send('Error submitting credit form. Please try again.');
    }
});

app.post('/submitDebitForm', upload.fields([
    { name: 'userPhoto' }, { name: 'userSignature' }
]), async (req, res) => {
    const files = req.files;
    const body = req.body;

    try {
        const newData = new DebitModel({
            ...body,
            dob: body.dob ? new Date(body.dob) : null,
            phone: body.phone ? Number(body.phone) : null,
            pin: body.pin ? Number(body.pin) : null,
            files: {
                userPhoto: files.userPhoto?.[0]?.path,
                userSignature: files.userSignature?.[0]?.path
            }
        });
        await newData.save();

        const pdfPath = `uploads/debit_${Date.now()}.pdf`;
        await generatePDF(body, pdfPath, {
            userPhoto: files.userPhoto?.[0]?.path,
            userSignature: files.userSignature?.[0]?.path
        });
        await emailPDF(body.email, pdfPath); // Use the general emailPDF function

        res.redirect('/success.html');
    } catch (error) {
        console.error("Error submitting debit form:", error);
        res.status(500).send('Error submitting debit form. Please try again.');
    }
});

app.post('/submitContactForm', async (req, res) => {
    const body = req.body;
    try {
        const newData = new ContactModel(body);
        await newData.save();

        const pdfPath = `uploads/contact_${Date.now()}.pdf`;
        await generatePDF(body, pdfPath);
        await emailPDF(body.email, pdfPath); // Use the general emailPDF function

        res.redirect('/success.html');
    } catch (error) {
        console.error("Error submitting contact form:", error);
        res.status(500).send('Error submitting contact form. Please try again.');
    }
});

// --- Serve HTML Forms (specific paths to avoid conflicts) ---
// Access these pages via http://localhost:3019/apply-credit, etc.
app.get('/apply-credit', (_, res) => res.sendFile(path.join(__dirname, 'apply_credit.html')));
app.get('/apply-debit', (_, res) => res.sendFile(path.join(__dirname, 'apply_debit.html')));
app.get('/contact-form', (_, res) => res.sendFile(path.join(__dirname, 'contact.html')));

// --- Default Root Route ---
// This will be the first page served when you go to http://localhost:3019/
// I've set it to your login page as it seems to be the entry point.
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// --- Start Server ---
app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
