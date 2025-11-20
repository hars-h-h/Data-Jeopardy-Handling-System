# Security Dashboard

A Node.js Express MySQL security dashboard application.

## Project Structure

- `database/` - Database schema and scripts
- `server/` - Express server and API endpoints
- `client/` - Frontend HTML/CSS/JavaScript
- `docs/` - Documentation and screenshots

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MySQL Server
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file based on `.env.example`:
   ```
   cp .env.example .env
   ```

4. Update `.env` with your MySQL credentials

5. Import the database schema:
   ```
   mysql -u root -p < database/schema.sql
   ```

### Running the Application

Development mode with auto-reload:
```
npm run dev
```

Production mode:
```
npm start
```

The application will be available at `http://localhost:5000`

## Features

- Security monitoring dashboard
- Real-time data visualization
- Database integration
- RESTful API endpoints

## License

ISC
