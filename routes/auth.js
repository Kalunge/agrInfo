const express = require('express');
const {
	register,
	login,
	getMe,
	logout,
	forgotPassword,
	resetPassword,
	updateDetails,
	updatePassword,
} = require('../controllers/auth');

const router = express.Router();
const { protect } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.get('/logout', logout);
router.get('/me', protect, getMe);
router.post('/forgotPassword', forgotPassword);
router.put('/updatepassword', protect, updatePassword);
router.put('/updatedetails', protect, updateDetails);
router.put('/resetPassword/:resettoken', resetPassword);

module.exports = router;
