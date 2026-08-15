const mongoose = require('mongoose');

// Controller: Simply return the active VidSrc domain configured by Django Admin
const getActiveDomain = async (req, res) => {
    try {
        const db = mongoose.connection.db;
        if (db) {
            const settings = await db.collection('systemsettings').findOne({ key: 'vidsrc_config' });
            if (settings && settings.active_domain) {
                return res.json({
                    ok: true,
                    active_domain: settings.active_domain,
                    auto_update: settings.auto_update || false
                });
            }
        }
        return res.json({ ok: true, active_domain: '' });
    } catch (error) {
        console.error('Error reading active vidsrc domain:', error);
        return res.json({ ok: false, error: error.message });
    }
};

module.exports = {
    getActiveDomain
};
