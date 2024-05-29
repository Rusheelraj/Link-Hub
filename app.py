from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import requests

app = Flask(__name__)

# Add your VirusTotal API key here
VT_API_KEY = 'd3454fbc3d37fe80e71b54d573f3a72a2e700de615dc69f82fd2f611fd576986'

def get_virustotal_report(url):
    params = {
        'apikey': VT_API_KEY,
        'resource': url
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    json_response = response.json()

    if response.status_code == 200:
        if json_response.get('response_code') == 1:
            # Report found
            return json_response.get('positives'), json_response.get('total')
        else:
            # No report found
            return 0, 0
    else:
        # Error occurred
        return None, None

def init_db():
    conn = sqlite3.connect('links.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS links
                 (id INTEGER PRIMARY KEY, url TEXT, positives INTEGER, total INTEGER)''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    conn = sqlite3.connect('links.db')
    c = conn.cursor()
    c.execute('SELECT * FROM links')
    links = c.fetchall()
    conn.close()
    return render_template('index.html', links=links)

@app.route('/add', methods=['POST'])
def add_link():
    url = request.form['url']
    positives, total = get_virustotal_report(url)
    conn = sqlite3.connect('links.db')
    c = conn.cursor()
    c.execute('INSERT INTO links (url, positives, total) VALUES (?, ?, ?)', (url, positives, total))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete/<int:id>', methods=['POST'])
def delete_link(id):
    conn = sqlite3.connect('links.db')
    c = conn.cursor()
    c.execute('DELETE FROM links WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)