const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require ('crypto');
const mailer = require('../../modules/mailer');

const authConfig = require('../../config/auth');

const User = require('../models/User');

const router = express.Router();

function generateToken(params = {}) {
    return jwt.sign(params, authConfig.secret, {
        expiresIn: 86400,
    });
}

router.post('/register', async (req, res) => {
    const { email } = req.body;
    try {
        if (await User.findOne({ email }))
            return res.status(400).send({ error: 'Usuario ja registrado' });

        const user = await User.create(req.body);


        user.password = undefined;

        return res.send({
            user,
            token: generateToken({ id: user.id }),
        });
    } catch (err) {
        return res.status(400).send({ error: 'Falha no registro' });
    }
});

router.post('/authenticate', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');

    if (!user)
        return res.status(400).send({ error: 'Usuario nao encontrado' });

    if (!await bcrypt.compare(password, user.password))
        return res.status(400).send({ error: 'Senha Incorreta' });

    user.password = undefined;

    res.send({
        user,
        token: generateToken({ id: user.id }),
    });
});

router.post('/forgot_password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user)
            return res.status(400).send({ error: 'Usuario nao encontrado' });

        const token = crypto.randomBytes(20).toString('hex');

        const now = new Date();
        now.setHours(now.getHours() + 1);

        await User.updateOne({_id: user.id,},
            { 
              passwordResetToken: token,
              passwordResetExpires: now,
          });
          
        mailer.sendMail({
        to: email,
        from: 'gmateu2030@gmal.com',
        template: 'auth/forgot_password',
        context: { token },

        }, (err) =>{
          if(err)
              return res.status(400).send({ error: 'Nao foi possivel enviar o email de recuperacao de senha'});
                
            return res.send();    
        })
    } catch (err) {
        console.log(err);
        res.status(400).send({ error: 'Erro na recuperacao de senha, tente novamente' });
    }
});

router.post('/reset_password', async(req, res) => {
const {email, token, password} = req.body;

try {
    const user = await User.findOne({ email })
    .select('+passwordResetToken passwordResetExpires');

    if (!user)
    return res.status(400).send({ error: 'Usuario nao encontrado' });

    if (token !== user.passwordResetToken)
        return res.status(400).send({ error: 'Token Invalido'});

    const now = new Date();
    
    if(now > user.passwordResetExpires)
        return res.status(400).send({ error: 'Token expirado, gere um novo'});

    user.password = password;
    
    await user.save();

    res.send();


} catch (err) {
    res.status(400).send({ error: 'Nao foi possivel restar a senha, tente novamente'});
    
}
});

module.exports = app => app.use('/auth', router);