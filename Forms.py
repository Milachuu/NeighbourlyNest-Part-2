from wtforms import Form,StringField,SelectField,TextAreaField,validators,PasswordField
from wtforms.fields import EmailField,FileField

class CreateUserForm(Form): 
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()]) 
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()]) 
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    password1 = PasswordField('Password',[validators.Length(min=7),validators.DataRequired(),validators.DataRequired(),validators.equal_to('password2',message="Passwords does not match")])
    password2 = PasswordField('Password (Confirm)',[validators.Length(min=7)])

class CreateUserInfo(Form): 
    username = StringField('Username',[validators.Length(min=3,max=25),validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()], choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='') 
    address = TextAreaField('Address', [validators.Length(max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone_number = StringField('Phone Number', [validators.DataRequired()])
    bio = TextAreaField('Bio', [validators.Optional()]) 

class Login(Form):
    email = EmailField('Email', [validators.Email(), validators.DataRequired()],render_kw={"placeholder":" Enter your email"})
    password = PasswordField('Password',[validators.Length(min=7)],render_kw={"placeholder":" Enter your password"})

class Update(Form):
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])

class Wishlist(Form):
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    item = StringField('Item', [validators.Length(min=1, max=150), validators.DataRequired()])
    description = TextAreaField('Description', [validators.Optional()])
   


class Reporting(Form):
    report_email = EmailField('User Email you wish to report', [validators.Email(), validators.DataRequired()])
    report_option = SelectField('Reasons', [validators.DataRequired()], choices=[('', 'Select'), ('Inappropriate Messages', 'Inappropriate messages'), ('Violation of Policies', 'Violation of Policies'),('other','other')], default='')
    report_other = TextAreaField('If you chose others, please write the reason here: ',[validators.length(max=200),validators.Optional()],default="")
    report_description = TextAreaField('Description', [validators.DataRequired()])



    