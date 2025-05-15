from flask import Flask, render_template, request, redirect, url_for, session, send_file


app = Flask(__name__)
app.config['SECRET_KEY'] = 'asdsdasd dasdasd'


"""Web App Routing"""

"""Before Login Homepage"""
@app.route('/')
def before_login():
    return render_template('home.html')

@app.route('/aboutUs')
def aboutUs():
    return render_template('aboutUs.html')

@app.route('/mission')
def mission():
    return render_template('mission.html')

@app.route('/feedbackb4')
def feedbackb4():
    return render_template('feedback before.html')

if __name__ == '__main__':
    app.run(debug=True)

