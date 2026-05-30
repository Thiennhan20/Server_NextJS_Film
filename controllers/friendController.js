const User = require('../models/User');
const Notification = require('../models/Notification');
const notificationService = require('../services/notificationService');

const createNotificationSafely = async (payload) => {
    try {
        await notificationService.createNotification(payload);
    } catch (error) {
        console.warn('Create notification failed:', error.message);
    }
};

// Send a friend request
const sendRequest = async (req, res) => {
    try {
        const { id } = req.params;
        const currentUserId = req.user;

        if (id === currentUserId.toString()) {
            return res.status(400).json({ message: "You cannot add yourself as a friend." });
        }

        const userToInvite = await User.findById(id);
        const currentUser = await User.findById(currentUserId);

        if (!userToInvite) {
            return res.status(404).json({ message: "User not found." });
        }

        // Check if already friends
        if (currentUser.friends.includes(id)) {
            return res.status(400).json({ message: "You are already friends." });
        }

        // Check if request already sent
        if (currentUser.sentFriendRequests.includes(id)) {
            return res.status(400).json({ message: "Friend request already sent." });
        }

        // Check if they already sent us a request
        if (currentUser.friendRequests.includes(id)) {
            return res.status(400).json({ message: "They already sent you a request. Please accept it." });
        }

        // Update sender's sentRequests and receiver's friendRequests
        currentUser.sentFriendRequests.push(id);
        userToInvite.friendRequests.push(currentUserId);

        await Promise.all([currentUser.save(), userToInvite.save()]);

        await createNotificationSafely({
            recipientId: id,
            actorId: currentUserId,
            type: 'friend_request',
            metadata: {}
        });

        res.json({ message: "Friend request sent successfully." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
};

// Accept a friend request
const acceptRequest = async (req, res) => {
    try {
        const { id } = req.params;
        const currentUserId = req.user;

        const currentUser = await User.findById(currentUserId);
        const requestingUser = await User.findById(id);

        if (!requestingUser) {
            return res.status(404).json({ message: "User not found." });
        }

        if (!currentUser.friendRequests.includes(id)) {
            return res.status(400).json({ message: "No friend request found." });
        }

        // Remove from requests, add to friends
        currentUser.friendRequests = currentUser.friendRequests.filter(reqId => reqId.toString() !== id);
        currentUser.friends.push(id);

        requestingUser.sentFriendRequests = requestingUser.sentFriendRequests.filter(reqId => reqId.toString() !== currentUserId.toString());
        requestingUser.friends.push(currentUserId);

        await Promise.all([currentUser.save(), requestingUser.save()]);

        // Delete the friend_request notification sent by the requesting user
        await Notification.deleteMany({
            recipient: currentUserId,
            actor: id,
            type: 'friend_request'
        });

        await createNotificationSafely({
            recipientId: requestingUser._id,
            actorId: currentUserId,
            type: 'friend_accept',
            metadata: {}
        });

        res.json({ message: "Friend request accepted." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
};

// Reject a friend request
const rejectRequest = async (req, res) => {
    try {
        const { id } = req.params;
        const currentUserId = req.user;

        const currentUser = await User.findById(currentUserId);
        const requestingUser = await User.findById(id);

        if (!requestingUser) {
            return res.status(404).json({ message: "User not found." });
        }

        // Remove from requests
        currentUser.friendRequests = currentUser.friendRequests.filter(reqId => reqId.toString() !== id);
        requestingUser.sentFriendRequests = requestingUser.sentFriendRequests.filter(reqId => reqId.toString() !== currentUserId.toString());

        await Promise.all([currentUser.save(), requestingUser.save()]);

        // Delete the friend_request notification
        await Notification.deleteMany({
            recipient: currentUserId,
            actor: id,
            type: 'friend_request'
        });

        res.json({ message: "Friend request rejected." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
};

// Cancel a sent friend request
const cancelRequest = async (req, res) => {
    try {
        const { id } = req.params;
        const currentUserId = req.user;

        const currentUser = await User.findById(currentUserId);
        const targetUser = await User.findById(id);

        if (!targetUser) {
            return res.status(404).json({ message: "User not found." });
        }

        // Remove from requests
        currentUser.sentFriendRequests = currentUser.sentFriendRequests.filter(reqId => reqId.toString() !== id);
        targetUser.friendRequests = targetUser.friendRequests.filter(reqId => reqId.toString() !== currentUserId.toString());

        await Promise.all([currentUser.save(), targetUser.save()]);

        // Delete the friend_request notification
        await Notification.deleteMany({
            recipient: id,
            actor: currentUserId,
            type: 'friend_request'
        });

        res.json({ message: "Friend request canceled." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
};

// Remove a friend
const removeFriend = async (req, res) => {
    try {
        const { id } = req.params;
        const currentUserId = req.user;

        const currentUser = await User.findById(currentUserId);
        const targetUser = await User.findById(id);

        if (!targetUser) {
            return res.status(404).json({ message: "User not found." });
        }

        currentUser.friends = currentUser.friends.filter(friendId => friendId.toString() !== id);
        targetUser.friends = targetUser.friends.filter(friendId => friendId.toString() !== currentUserId.toString());

        await Promise.all([currentUser.save(), targetUser.save()]);

        // Delete any friend_request or friend_accept notifications between the two users
        await Notification.deleteMany({
            $or: [
                { recipient: currentUserId, actor: id, type: { $in: ['friend_request', 'friend_accept'] } },
                { recipient: id, actor: currentUserId, type: { $in: ['friend_request', 'friend_accept'] } }
            ]
        });

        res.json({ message: "Friend removed." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
};

// Get all friend info (friends list, sent requests, received requests)
const getFriendsData = async (req, res) => {
    try {
        const currentUser = await User.findById(req.user)
            .populate('friends', 'name avatar originalAvatar createdAt')
            .populate('friendRequests', 'name avatar originalAvatar createdAt')
            .populate('sentFriendRequests', 'name avatar originalAvatar createdAt');

        if (!currentUser) {
            return res.status(404).json({ message: "User not found." });
        }

        res.json({
            friends: currentUser.friends,
            friendRequests: currentUser.friendRequests,
            sentFriendRequests: currentUser.sentFriendRequests
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
};

module.exports = {
    sendRequest,
    acceptRequest,
    rejectRequest,
    cancelRequest,
    removeFriend,
    getFriendsData
};
