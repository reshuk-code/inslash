const ejs = require('ejs');
const path = require('path');

/**
 * Render an email template with layout
 * @param {string} template - Template name (e.g., 'welcome', 'otp', 'verify-email', 'login-alert')
 * @param {Object} data - Data to pass to the template
 * @param {string} data.title - Email title
 * @returns {Promise\u003cstring\u003e} - Rendered HTML
 */
async function renderEmail(template, data) {
    try {
        const templatePath = path.join(__dirname, '..', 'views', 'emails', `${template}.ejs`);
        const layoutPath = path.join(__dirname, '..', 'views', 'emails', 'layout.ejs');

        // Render the template content
        const bodyContent = await ejs.renderFile(templatePath, data);

        // Render the layout with the body content
        const html = await ejs.renderFile(layoutPath, {
            title: data.title || 'Inslash',
            body: bodyContent
        });

        return html;
    } catch (error) {
        console.error('Email render error:', error);
        throw error;
    }
}

/**
 * Send an email using the configured transporter
 * @param {Object} transporter - Nodemailer transporter
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email
 * @param {string} options.subject - Email subject
 * @param {string} options.template - Template name
 * @param {Object} options.data - Template data
 * @returns {Promise\u003cvoid\u003e}
 */
async function sendTemplatedEmail(transporter, options) {
    const { to, subject, template, data } = options;

    const html = await renderEmail(template, data);

    await transporter.sendMail({
        from: '"Inslash" \u003cnoreply@inslash.antqr.xyz\u003e',
        to,
        subject,
        html
    });
}

module.exports = {
    renderEmail,
    sendTemplatedEmail
};
