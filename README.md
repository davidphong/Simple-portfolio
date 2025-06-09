# Developer Portfolio Management

A full-stack web application for developers to create and manage their professional portfolios.

## Features

- User authentication (login, register, password reset)
- Profile management
- Project management
- Public portfolio page
- Contact form

## Tech Stack

### Frontend
- React
- React Router
- Zustand (state management)
- Axios (API client)
- CSS

### Backend
- Flask (Python web framework)
- Flask-SQLAlchemy (ORM)
- Flask-JWT-Extended (authentication)
- MySQL (database)
- Flask-Mail (email service)

## Getting Started

### Prerequisites
- Docker and Docker Compose
- Node.js (for local development)
- Python (for local development)

### Running with Docker

1. Clone the repository
2. Create a `.env` file in the root directory with the following variables:
   ```
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_app_password
   ```
3. Run the application:
   ```
   docker-compose up
   ```
4. Access the application:
   - Frontend: http://localhost:9745
   - Backend API: http://localhost:7331

### Development Setup

#### Backend
1. Navigate to the backend directory:
   ```
   cd backend
   ```
2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the Flask app:
   ```
   python app.py
   ```

#### Frontend
1. Navigate to the frontend directory:
   ```
   cd frontend
   ```
2. Install dependencies:
   ```
   npm install
   ```
3. Run the React app:
   ```
   npm start
   ```

## API Endpoints

- `POST /api/user/signup`: Create a new user account
- `POST /api/user/login`: Log in with email and password
- `POST /api/user/forgot-password`: Send a magic link to reset password
- `POST /api/user/reset-password`: Reset password using magic link
- `GET /api/user/profile`: Get user profile
- `PUT /api/user/profile`: Update user profile
- `GET /api/user/projects`: Get user projects
- `POST /api/user/projects`: Add a new project
- `PUT /api/user/projects/:id`: Update a project
- `DELETE /api/user/projects/:id`: Delete a project
- `GET /api/portfolio/:id`: Get public portfolio
- `POST /api/contact`: Send contact message

## License

This project is licensed under the MIT License. 