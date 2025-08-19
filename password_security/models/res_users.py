# Copyright 2016 LasLabs Inc.
# Copyright 2017 Kaushal Prajapati <kbprajapati@live.com>.
# Copyright 2018 Modoolar <info@modoolar.com>.
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

import logging
import re

from datetime import datetime, timedelta

from odoo import api, fields, models, _

from ..exceptions import PassError


_logger = logging.getLogger(__name__)
try:
    import zxcvbn
except ImportError:
    _logger.debug(
        'Could not import zxcvbn. Please make sure this library is available in your environment.'
    )


def delta_now(**kwargs):
    dt = datetime.now() + timedelta(**kwargs)
    return fields.Datetime.to_string(dt)


class ResUsers(models.Model):
    _inherit = 'res.users'

    password_write_date = fields.Datetime(
        'Last password update',
        default=fields.Datetime.now,
        readonly=True,
    )

    password_history_ids = fields.One2many(
        string='Password History',
        comodel_name='res.users.pass.history',
        inverse_name='user_id',
        readonly=True,
    )

    @api.model
    def create(self, vals):
        vals['password_write_date'] = fields.Datetime.now()
        return super(ResUsers, self).create(vals)

    @api.multi
    def write(self, vals):
        if vals.get('password'):
            self._check_password(vals['password'])
            vals['password_write_date'] = fields.Datetime.now()

        return super(ResUsers, self).write(vals)

    @api.model
    def get_password_policy(self):
        data = super(ResUsers, self).get_password_policy()

        get_param = self.env['ir.config_parameter'].sudo().get_param

        password_lower = get_param('password_security.password_lower', '0')
        password_upper = get_param('password_security.password_upper', '0')
        password_numeric = get_param('password_security.password_numeric', '0')
        password_special = get_param('password_security.password_special', '0')
        password_length = get_param('password_security.password_length', '0')
        password_estimate = get_param('password_security.password_estimate', '0')

        data.update(
            {
                "password_lower": int(password_lower),
                "password_upper": int(password_upper),
                "password_numeric": int(password_numeric),
                "password_special": int(password_special),
                "password_length": int(password_length),
                "password_estimate": int(password_estimate),
            }
        )

        if 'minlength' in data:
            data['minlength'] = int(password_length)

        return data

    def _check_password_policy(self, passwords):
        # result = super(ResUsers, self)._check_password_policy(passwords)

        for password in passwords:
            if not password:
                continue
            self._check_password(password)

        return True

    @api.model
    def get_estimation(self, password):
        return zxcvbn.zxcvbn(password)

    @api.multi
    def password_match_message(self):
        self.ensure_one()
        get_param = self.env['ir.config_parameter'].sudo().get_param

        password_lower = get_param('password_security.password_lower', '0')
        password_upper = get_param('password_security.password_upper', '0')
        password_numeric = get_param('password_security.password_numeric', '0')
        password_special = get_param('password_security.password_special', '0')
        password_length = get_param('password_security.password_length', '0')

        message = []
        if password_lower:
            message.append('\n* ' + 'Lowercase letter (At least ' + password_lower + ' character)')

        if password_upper:
            message.append('\n* ' + 'Uppercase letter (At least ' + password_upper + ' character)')

        if password_numeric:
            message.append('\n* ' + 'Numeric digit (At least ' + password_numeric + ' character)')

        if password_special:
            message.append('\n* ' + 'Special character (At least ' + password_special + ' character)')

        if message:
            message = [_('Must contain the following:')] + message

        if password_length:
            message = ['Password must be ' + password_length + ' characters or more.'] + message

        return '\r'.join(message)

    @api.multi
    def _check_password(self, password):
        self._check_password_rules(password)
        self._check_password_history(password)
        return True

    @api.multi
    def _check_password_rules(self, password):
        self.ensure_one()
        if not password:
            return True

        get_param = self.env['ir.config_parameter'].sudo().get_param

        password_lower = get_param('password_security.password_lower', '0')
        password_upper = get_param('password_security.password_upper', '0')
        password_numeric = get_param('password_security.password_numeric', '0')
        password_special = get_param('password_security.password_special', '0')
        password_length = get_param('password_security.password_length', '0')
        password_estimate = get_param('password_security.password_estimate', '0')

        password_regex = [
            '^',
            '(?=.*?[a-z]){' + password_lower + ',}',
            '(?=.*?[A-Z]){' + password_upper + ',}',
            '(?=.*?\\d){' + password_numeric + ',}',
            r'(?=.*?[\W_]){' + password_special + ',}',
            '.{%d,}$' % int(password_length),
        ]

        if not re.search(''.join(password_regex), password):
            raise PassError(self.password_match_message())

        estimation = self.get_estimation(password)
        if estimation["score"] < int(password_estimate):
            raise PassError(estimation["feedback"]["warning"])

        return True

    @api.multi
    def _password_has_expired(self):
        """
        Verifica se a senha do usuário expirou conforme a política definida.

        Melhorias de performance:
        - Busca o parâmetro de expiração apenas uma vez.
        - Utiliza cálculo direto de diferença de datas sem conversão desnecessária.
        - Evita exceções genéricas, tratando apenas erros esperados.

        :return: True se a senha expirou, False caso contrário.
        """
        self.ensure_one()
        get_param = self.env['ir.config_parameter'].sudo().get_param
        password_expiration = get_param('password_security.password_expiration', 0)

        if not isinstance(password_expiration, int):
            try:
                password_expiration = int(password_expiration)
            except (TypeError, ValueError):
                password_expiration = 0

        if not self.password_write_date:
            return True

        if not password_expiration:
            return False

        try:
            # Calcula a diferença em dias diretamente usando datetime
            write_date = fields.Datetime.from_string(self.password_write_date)
            now = datetime.now()
            days = (now - write_date).days
            return days > password_expiration
        except (TypeError, ValueError):
            # Em caso de erro na conversão, considera não expirado
            return False

    @api.multi
    def action_expire_password(self):
        expiration = delta_now(days=+1)
        for rec_id in self:
            rec_id.mapped('partner_id').signup_prepare(
                signup_type="reset", expiration=expiration
            )

    @api.multi
    def _validate_pass_reset(self):
        """ It provides validations before initiating a pass reset email
        :raises: PassError on invalidated pass reset attempt
        :return: True on allowed reset
        """
        get_param = self.env['ir.config_parameter'].sudo().get_param
        pass_min = get_param('password_security.password_minimum', 0)

        if pass_min > 0:
            for rec_id in self:
                write_date = rec_id.password_write_date
                delta = timedelta(hours=pass_min)

                if write_date + delta > datetime.now():
                    raise PassError(
                        _('Passwords can only be reset every %d hour(s). '
                        'Please contact an administrator for assistance.') %
                        pass_min,
                    )

        return True

    @api.multi
    def _check_password_history(self, password):
        """
        Valida a senha proposta contra o histórico de senhas do usuário.
        Levanta PassError se a senha já foi utilizada recentemente.

        Melhorias de performance:
        - Busca apenas os registros necessários do histórico.
        - Utiliza mapeamento direto ao invés de filtered para evitar lambda lento.
        """
        crypt = self._crypt_context()
        get_param = self.env['ir.config_parameter'].sudo().get_param
        password_history = int(get_param('password_security.password_history', '0'))

        # password_history: número negativo para infinito, 0 para desabilitar
        if password_history != 0:
            for rec_id in self:
                # Seleciona apenas os registros necessários do histórico
                if password_history < 0:
                    recent_passes = rec_id.password_history_ids
                else:
                    recent_passes = rec_id.password_history_ids[:password_history - 1]

                # Verifica se alguma senha do histórico corresponde à senha proposta
                for pass_hist in recent_passes:
                    if crypt.verify(password, pass_hist.password_crypt):
                        raise PassError(
                            _("Cannot use the most recent %d passwords")
                            % get_param("password_security.password_history", "0")
                        )

    def _set_encrypted_password(self, uid, pw):
        """ It saves password crypt history for history rules """
        super(ResUsers, self)._set_encrypted_password(uid, pw)

        self.env["res.users.pass.history"].create({
            "user_id": uid,
            "password_crypt": pw
        })
