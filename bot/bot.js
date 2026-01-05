const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes, EmbedBuilder } = require('discord.js');
const crypto = require('crypto');
const Panel = require('../models/Panel');
const License = require('../models/License');
const HWIDAccess = require('../models/HWIDAccess');
const User = require('../models/User');

const initBot = () => {
    const client = new Client({ intents: [GatewayIntentBits.Guilds] });

    client.once('ready', async () => {
        console.log(`🤖 Bot logged in as ${client.user.tag}`);

        const commands = [
            new SlashCommandBuilder()
                .setName('panel')
                .setDescription('Panel management')
                .addSubcommand(sub => sub.setName('create').setDescription('Create a new panel').addStringOption(opt => opt.setName('name').setDescription('Panel name').setRequired(true)))
                .addSubcommand(sub => sub.setName('delete').setDescription('Delete a panel').addStringOption(opt => opt.setName('name').setDescription('Panel name').setRequired(true).setAutocomplete(true)))
                .addSubcommand(sub => sub.setName('list').setDescription('List your panels')),

            new SlashCommandBuilder()
                .setName('user')
                .setDescription('User management')
                .addSubcommand(sub =>
                    sub.setName('add')
                        .setDescription('Add a new user')
                        .addStringOption(opt => opt.setName('panel').setDescription('Panel name').setRequired(true).setAutocomplete(true))
                        .addStringOption(opt => opt.setName('username').setDescription('Username').setRequired(true))
                        .addIntegerOption(opt => opt.setName('days').setDescription('Expiry days').setRequired(true))
                        .addStringOption(opt => opt.setName('password').setDescription('Password (Optional)').setRequired(false))
                )
                .addSubcommand(sub =>
                    sub.setName('update')
                        .setDescription('Update user status/password')
                        .addStringOption(opt => opt.setName('panel').setDescription('Panel name').setRequired(true).setAutocomplete(true))
                        .addStringOption(opt => opt.setName('username').setDescription('Username').setRequired(true).setAutocomplete(true))
                        .addStringOption(opt => opt.setName('status').setDescription('Status').addChoices({ name: 'Active', value: 'active' }, { name: 'Pause', value: 'pause' }, { name: 'Ban', value: 'ban' }))
                        .addStringOption(opt => opt.setName('password').setDescription('New Password'))
                )
                .addSubcommand(sub =>
                    sub.setName('delete')
                        .setDescription('Delete user')
                        .addStringOption(opt => opt.setName('panel').setDescription('Panel name').setRequired(true).setAutocomplete(true))
                        .addStringOption(opt => opt.setName('username').setDescription('Username').setRequired(true).setAutocomplete(true))
                )
                .addSubcommand(sub =>
                    sub.setName('resethwid')
                        .setDescription('Reset user HWID')
                        .addStringOption(opt => opt.setName('panel').setDescription('Panel name').setRequired(true).setAutocomplete(true))
                        .addStringOption(opt => opt.setName('username').setDescription('Username').setRequired(true).setAutocomplete(true))
                ),

            new SlashCommandBuilder()
                .setName('hwid')
                .setDescription('HWID whitelist management')
                .addSubcommand(sub =>
                    sub.setName('add')
                        .setDescription('Add HWID to whitelist')
                        .addStringOption(opt => opt.setName('panel').setDescription('Panel name').setRequired(true).setAutocomplete(true))
                        .addStringOption(opt => opt.setName('hwid').setDescription('HWID string').setRequired(true))
                        .addStringOption(opt => opt.setName('name').setDescription('Label for HWID').setRequired(true))
                        .addIntegerOption(opt => opt.setName('days').setDescription('Expiry days (empty for infinite)'))
                )
                .addSubcommand(sub =>
                    sub.setName('delete')
                        .setDescription('Remove HWID from whitelist')
                        .addStringOption(opt => opt.setName('panel').setDescription('Panel name').setRequired(true).setAutocomplete(true))
                        .addStringOption(opt => opt.setName('hwid').setDescription('HWID string').setRequired(true).setAutocomplete(true))
                )
        ].map(command => command.toJSON());

        const rest = new REST({ version: '10' }).setToken(process.env.BOT_TOKEN);
        try {
            await rest.put(Routes.applicationGuildCommands(client.user.id, process.env.GUILD_ID), { body: commands });
            console.log('✅ Updated slash commands registered.');
        } catch (error) {
            console.error('❌ Bot Slash Error:', error);
        }
    });

    client.on('interactionCreate', async interaction => {
        const getOwnerQuery = async (id) => {
            const dbUser = await User.findOne({ discordId: id });
            const q = { $or: [{ ownerId: id }] };
            if (dbUser) q.$or.push({ ownerId: dbUser._id.toString() });
            return q;
        };

        if (interaction.isAutocomplete()) {
            const { commandName, options, user } = interaction;
            const focusedOption = options.getFocused(true);
            const ownerId = user.id;

            if (focusedOption.name === 'panel') {
                const ownerQuery = await getOwnerQuery(ownerId);
                const panels = await Panel.find({ ...ownerQuery, name: { $regex: focusedOption.value, $options: 'i' } }).limit(25);
                await interaction.respond(panels.map(p => ({ name: p.name, value: p.name })));
            }

            if (focusedOption.name === 'username') {
                const panelName = options.getString('panel');
                if (!panelName) return interaction.respond([]);
                const ownerQuery = await getOwnerQuery(ownerId);
                const panel = await Panel.findOne({ name: panelName, ...ownerQuery });
                if (!panel) return interaction.respond([]);

                const users = await License.find({
                    panelId: panel._id,
                    username: { $regex: focusedOption.value, $options: 'i' }
                }).limit(25);
                await interaction.respond(users.map(u => ({ name: u.username, value: u.username })));
            }

            if (focusedOption.name === 'hwid' && commandName === 'hwid') {
                const panelName = options.getString('panel');
                if (!panelName) return interaction.respond([]);
                const ownerQuery = await getOwnerQuery(ownerId);
                const panel = await Panel.findOne({ name: panelName, ...ownerQuery });
                if (!panel) return interaction.respond([]);

                const hwids = await HWIDAccess.find({
                    panelId: panel._id,
                    hwid: { $regex: focusedOption.value, $options: 'i' }
                }).limit(25);
                await interaction.respond(hwids.map(h => ({ name: `${h.name} (${h.hwid.slice(0, 10)}...)`, value: h.hwid })));
            }
            return;
        }

        if (!interaction.isChatInputCommand()) return;

        const { commandName, options, user } = interaction;
        const ownerId = user.id;

        // --- Panel Commands ---
        if (commandName === 'panel') {
            const sub = options.getSubcommand();
            if (sub === 'create') {
                const name = options.getString('name');
                try {
                    const secret = crypto.randomBytes(16).toString('hex');
                    // Prefer discordId if we can, but since this is bot, ownerId is Discord ID.
                    await new Panel({ ownerId, name, secret }).save();
                    await interaction.reply({ content: `✅ Panel **${name}** created.\nSecret: ||${secret}||`, ephemeral: true });
                } catch (err) { await interaction.reply({ content: '❌ Error creating panel.', ephemeral: true }); }
            } else if (sub === 'delete') {
                const name = options.getString('name');
                const ownerQuery = await getOwnerQuery(ownerId);
                const panel = await Panel.findOneAndDelete({ name, ...ownerQuery });
                if (panel) {
                    await License.deleteMany({ panelId: panel._id });
                    await HWIDAccess.deleteMany({ panelId: panel._id });
                    await interaction.reply({ content: `✅ Panel **${name}** and data deleted.`, ephemeral: true });
                } else await interaction.reply({ content: '❌ Panel not found.', ephemeral: true });
            } else if (sub === 'list') {
                const ownerQuery = await getOwnerQuery(ownerId);
                const panels = await Panel.find(ownerQuery);
                const list = panels.map(p => `• **${p.name}** (Secret: ||${p.secret}||)`).join('\n') || 'No panels.';
                await interaction.reply({ content: `**Your Panels:**\n${list}`, ephemeral: true });
            }
        }

        // --- User Commands ---
        if (commandName === 'user') {
            const sub = options.getSubcommand();
            const panelName = options.getString('panel');
            const ownerQuery = await getOwnerQuery(ownerId);
            const panel = await Panel.findOne({ name: panelName, ...ownerQuery });
            if (!panel) return interaction.reply({ content: '❌ Invalid panel.', ephemeral: true });

            const username = options.getString('username');

            if (sub === 'add') {
                const password = options.getString('password') || "";
                const days = options.getInteger('days');
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + days);
                try {
                    await new License({ username, password, panelId: panel._id, expiryDate }).save();
                    const passMsg = password ? ` (Password: ||${password}||)` : ' (No password)';
                    await interaction.reply({ content: `✅ User **${username}** added to **${panelName}**${passMsg}.`, ephemeral: true });
                } catch (err) { await interaction.reply({ content: '❌ Error adding user.', ephemeral: true }); }
            } else if (sub === 'update') {
                const status = options.getString('status');
                const password = options.getString('password');
                const updates = {};
                if (status) updates.status = status;
                if (password) updates.password = password;
                const res = await License.findOneAndUpdate({ username, panelId: panel._id }, { $set: updates });
                if (res) await interaction.reply({ content: `✅ User **${username}** updated.`, ephemeral: true });
                else await interaction.reply({ content: '❌ User not found.', ephemeral: true });
            } else if (sub === 'delete') {
                const res = await License.findOneAndDelete({ username, panelId: panel._id });
                if (res) await interaction.reply({ content: `✅ User **${username}** deleted.`, ephemeral: true });
                else await interaction.reply({ content: '❌ User not found.', ephemeral: true });
            } else if (sub === 'resethwid') {
                const res = await License.findOneAndUpdate({ username, panelId: panel._id }, { $set: { hwid: null } });
                if (res) await interaction.reply({ content: `✅ HWID reset for **${username}**.`, ephemeral: true });
                else await interaction.reply({ content: '❌ User not found.', ephemeral: true });
            }
        }

        // --- HWID Commands ---
        if (commandName === 'hwid') {
            const sub = options.getSubcommand();
            const panelName = options.getString('panel');
            const ownerQuery = await getOwnerQuery(ownerId);
            const panel = await Panel.findOne({ name: panelName, ...ownerQuery });
            if (!panel) return interaction.reply({ content: '❌ Invalid panel.', ephemeral: true });

            const hwidVal = options.getString('hwid');

            if (sub === 'add') {
                const name = options.getString('name');
                const days = options.getInteger('days');
                let expiryDate = null;
                if (days) {
                    expiryDate = new Date();
                    expiryDate.setDate(expiryDate.getDate() + days);
                }
                try {
                    await new HWIDAccess({ panelId: panel._id, hwid: hwidVal, name, expiryDate }).save();
                    const expiryMsg = days ? ` (Expires in ${days} days)` : ' (Infinite)';
                    await interaction.reply({ content: `✅ HWID added to whitelist for **${panelName}**${expiryMsg}.`, ephemeral: true });
                } catch (err) { await interaction.reply({ content: '❌ Error adding HWID.', ephemeral: true }); }
            } else if (sub === 'delete') {
                const res = await HWIDAccess.findOneAndDelete({ panelId: panel._id, hwid: hwidVal });
                if (res) await interaction.reply({ content: `✅ HWID removed from whitelist.`, ephemeral: true });
                else await interaction.reply({ content: '❌ HWID not found in whitelist.', ephemeral: true });
            }
        }
    });

    client.login(process.env.BOT_TOKEN).catch(err => console.error('❌ Bot Login Error:', err));
};

module.exports = { initBot };
