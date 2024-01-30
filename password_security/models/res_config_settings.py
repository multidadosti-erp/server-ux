# Copyright 2018 Modoolar <info@modoolar.com>
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).
from odoo import api, models, fields, _
from odoo.exceptions import ValidationError


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    password_expiration = fields.Integer(
        string='Days',
        default=0,
        help='How many days until passwords expire',
        config_parameter="password_security.password_expiration",
    )

    password_length = fields.Integer(
        string='Characters',
        default=4,
        help='Minimum number of characters',
        config_parameter="password_security.password_length",
    )

    password_lower = fields.Integer(
        string='Lowercase',
        default=0,
        help='Require number of lowercase letters',
        config_parameter="password_security.password_lower",
    )

    password_upper = fields.Integer(
        string='Uppercase',
        default=0,
        help='Require number of uppercase letters',
        config_parameter="password_security.password_upper",
    )

    password_numeric = fields.Integer(
        string='Numeric',
        default=0,
        help='Require number of numeric digits',
        config_parameter="password_security.password_numeric",
    )

    password_special = fields.Integer(
        string='Special',
        default=0,
        help='Require number of unique special characters',
        config_parameter="password_security.password_special",
    )

    password_estimate = fields.Integer(
        string='Estimation',
        default=0,
        help='Required score for the strength estimation. Between 0 and 4',
        config_parameter="password_security.password_estimate",
    )

    password_history = fields.Integer(
        string='History',
        default=-1,
        help='Disallow reuse of this many previous passwords - use negative number for infinite, or 0 to disable',
        config_parameter="password_security.password_history",
    )

    password_minimum = fields.Integer(
        string='Minimum Hours',
        default=0,
        help='Amount of hours until a user may change password again',
        config_parameter="password_security.password_minimum",
    )

    @api.constrains('password_estimate')
    def _check_password_estimate(self):
        if 0 > self.password_estimate > 4:
            raise ValidationError(_('The estimation must be between 0 and 4.'))
