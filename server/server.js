const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');

// Load environment variables from .env if present
require('dotenv').config();

const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_USER = process.env.DB_USER || 'root_harsh';
const DB_PASS = process.env.DB_PASS || 'Harshraj@22';
const DB_NAME = process.env.DB_NAME || 'DataJeopardyDB';
const API_PORT = parseInt(process.env.API_PORT, 10) || 5000;

// Auto-lock when RiskScore >= threshold
const AUTO_LOCK_RISK_THRESHOLD = parseInt(process.env.AUTO_LOCK_RISK_THRESHOLD, 10) || 60;

const pool = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Classify query and return threat type
function classifyQuery(query) {
  const q = (query || '').toUpperCase();
  if (!q) return 'NORMAL_QUERY';
  
  if (q.includes('DROP TABLE') || q.includes('DROP DATABASE')) return 'SQL_INJECTION_DROP';
  if (q.includes('DELETE FROM')) return 'SQL_INJECTION_DELETE';
  if (q.includes('ALTER TABLE')) return 'SQL_INJECTION_ALTER';
  if (q.includes('TRUNCATE')) return 'SQL_INJECTION_TRUNCATE';
  if (q.includes('GRANT') || q.includes('REVOKE')) return 'PRIVILEGE_ESCALATION';
  if (q.includes('PASSWORD') || q.includes('CREDITCARD') || q.includes('SSN') || q.includes('CARD')) return 'SENSITIVE_DATA_ACCESS';
  if (q.includes('INSERT') || q.includes('UPDATE')) return 'DATA_MODIFICATION';
  
  return 'NORMAL_QUERY';
}

function sha256(s) {
  return crypto.createHash('sha256').update(s || '').digest('hex');
}

async function computeUserRiskAndFlags(rows) {
  if (!rows || !rows.length) return [];
  const userIds = rows.map(r => r.UserID);

  const conn = await pool.getConnection();

  try {
    const [counts] = await conn.query(
      `SELECT UserID,
              SUM(CASE WHEN Severity='HIGH' THEN 1 ELSE 0 END) AS HighCnt,
              SUM(CASE WHEN Severity='HIGH' AND Timestamp >= DATE_SUB(NOW(), INTERVAL 30 MINUTE) THEN 1 ELSE 0 END) AS RecentHigh
       FROM Audit_Log
       WHERE UserID IN (?)
       GROUP BY UserID`,
      [userIds]
    );

    const map = {};
    counts.forEach(r => map[r.UserID] = r);

    return rows.map(u => {
      const hc = (map[u.UserID]?.HighCnt) || 0;
      const recent = (map[u.UserID]?.RecentHigh) || 0;

      const riskScore = Math.min(100, hc * 15 + (u.Status === 'LOCKED' ? 30 : 0));
      const shouldAutoLock = u.RoleID !== 1 && u.Status === 'ACTIVE' && riskScore >= AUTO_LOCK_RISK_THRESHOLD;

      return {
        ...u,
        HighSeverityCount: hc,
        RecentHighCount: recent,
        RiskScore: riskScore,
        ShouldAutoLock: shouldAutoLock
      };
    });

  } finally {
    conn.release();
  }
}

// Get handler routine based on threat type and user role
async function getHandlerRoutine(conn, threatType, userRoleId) {
  // Admin actions always use ADMIN_ACTION routine
  if (userRoleId === 1) {
    const [routines] = await conn.query(
      'SELECT * FROM Handler_Routine WHERE ThreatType = ? LIMIT 1',
      ['ADMIN_ACTION']
    );
    return routines[0] || null;
  }

  // Get appropriate handler routine for the threat type
  const [routines] = await conn.query(
    'SELECT * FROM Handler_Routine WHERE ThreatType = ? LIMIT 1',
    [threatType]
  );

  return routines[0] || null;
}

// ---------------------- EXISTING ROUTES ---------------------- //

app.get('/roles', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT RoleID, RoleName FROM Role ORDER BY RoleID');
    res.json({ ok: true, roles: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/users', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const [rows] = await conn.query(
      `SELECT u.UserID, u.Username, u.Status, u.RoleID, r.RoleName,
              u.LastLogin, u.FailedLoginAttempts
       FROM UserAccount u
       LEFT JOIN Role r ON u.RoleID = r.RoleID
       ORDER BY u.UserID`
    );

    const enhanced = await computeUserRiskAndFlags(rows);

    const toLock = enhanced.filter(u =>
      u.RoleID !== 1 &&
      u.Status === 'ACTIVE' &&
      u.RiskScore >= AUTO_LOCK_RISK_THRESHOLD
    );

    if (toLock.length > 0) {
      await conn.beginTransaction();

      // Get AUTO_LOCK routine
      const [autoLockRoutine] = await conn.query(
        'SELECT RoutineID FROM Handler_Routine WHERE ThreatType = ? LIMIT 1',
        ['AUTO_LOCK']
      );
      const routineId = autoLockRoutine[0]?.RoutineID || null;

      for (const u of toLock) {
        await conn.query(
          'UPDATE UserAccount SET Status = ? WHERE UserID = ?',
          ['LOCKED', u.UserID]
        );

        await conn.query(
          'INSERT INTO Audit_Log (UserID, QueryText, Severity, ActionTaken, RoutineID) VALUES (?, ?, ?, ?, ?)',
          [u.UserID,
           `AUTO-LOCK (RiskScore ${u.RiskScore})`,
           'HIGH',
           'Account auto-locked',
           routineId]
        );
      }

      await conn.commit();

      const [fresh] = await pool.query(
        `SELECT u.UserID, u.Username, u.Status, u.RoleID, r.RoleName,
                u.LastLogin, u.FailedLoginAttempts
         FROM UserAccount u
         LEFT JOIN Role r ON u.RoleID = r.RoleID
         ORDER BY u.UserID`
      );

      const refreshed = await computeUserRiskAndFlags(fresh);
      return res.json({ ok: true, users: refreshed });
    }

    res.json({ ok: true, users: enhanced });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});


app.get('/logs', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
        al.LogID, 
        al.UserID, 
        al.QueryText, 
        al.Severity, 
        al.ActionTaken, 
        al.Timestamp,
        hr.RoutineName,
        hr.ThreatType
       FROM Audit_Log al
       LEFT JOIN Handler_Routine hr ON al.RoutineID = hr.RoutineID
       ORDER BY al.Timestamp DESC
       LIMIT 200`
    );

    res.json({ ok: true, logs: rows });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.get('/handler-routines', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
        RoutineID, 
        RoutineName, 
        ThreatType, 
        ResponseAction, 
        Severity, 
        Description, 
        AutoLock, 
        NotifyAdmin 
       FROM Handler_Routine 
       ORDER BY Severity DESC, RoutineName`
    );

    res.json({ ok: true, routines: rows });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.get('/handler-stats', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
        hr.RoutineID,
        hr.RoutineName,
        hr.ThreatType,
        hr.Severity,
        COUNT(al.LogID) AS UsageCount
       FROM Handler_Routine hr
       LEFT JOIN Audit_Log al ON hr.RoutineID = al.RoutineID
       GROUP BY hr.RoutineID, hr.RoutineName, hr.ThreatType, hr.Severity
       ORDER BY UsageCount DESC`
    );

    res.json({ ok: true, stats: rows });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.post('/add-user', async (req, res) => {
  try {
    const { username, password, roleId } = req.body;
    if (!username || !password || !roleId)
      return res.status(400).json({ ok: false, error: 'Missing fields' });

    const passwordHash = sha256(password);

    const conn = await pool.getConnection();
    const [result] = await conn.query(
      'INSERT INTO UserAccount (Username, PasswordHash, RoleID, Status) VALUES (?, ?, ?, ?)',
      [username, passwordHash, roleId, 'ACTIVE']
    );

    conn.release();
    res.json({ ok: true, insertedId: result.insertId });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.post('/add-log', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const { userId, query, severity: providedSeverity } = req.body;
    if (!userId || !query)
      return res.status(400).json({ ok: false, error: 'Missing fields' });

    // Get user role
    const [userRows] = await conn.query(
      'SELECT RoleID FROM UserAccount WHERE UserID = ?',
      [userId]
    );
    
    if (userRows.length === 0) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }

    const userRoleId = userRows[0].RoleID;

    // Classify the query to determine threat type
    const threatType = classifyQuery(query);

    // Get the appropriate handler routine
    const handlerRoutine = await getHandlerRoutine(conn, threatType, userRoleId);

    if (!handlerRoutine) {
      return res.status(500).json({ ok: false, error: 'No handler routine found' });
    }

    // Use handler routine's severity or provided severity
    const severity = providedSeverity || handlerRoutine.Severity;
    const actionTaken = handlerRoutine.ResponseAction;
    const routineId = handlerRoutine.RoutineID;

    await conn.beginTransaction();

    const [insertResult] = await conn.query(
      'INSERT INTO Audit_Log (UserID, QueryText, Severity, ActionTaken, RoutineID) VALUES (?, ?, ?, ?, ?)',
      [userId, query, severity, actionTaken, routineId]
    );

    await conn.commit();

    res.json({ 
      ok: true, 
      logId: insertResult.insertId,
      handlerRoutine: {
        name: handlerRoutine.RoutineName,
        threatType: handlerRoutine.ThreatType,
        action: actionTaken,
        severity: severity
      }
    });

  } catch (e) {
    await conn.rollback();
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});


app.post('/lock-user', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const { userId } = req.body;

    if (!userId)
      return res.status(400).json({ ok: false, error: 'Missing userId' });

    await conn.beginTransaction();

    await conn.query(
      'UPDATE UserAccount SET Status = ? WHERE UserID = ?',
      ['LOCKED', userId]
    );

    // Get MANUAL_LOCK routine
    const [lockRoutine] = await conn.query(
      'SELECT RoutineID FROM Handler_Routine WHERE ThreatType = ? LIMIT 1',
      ['MANUAL_LOCK']
    );
    const routineId = lockRoutine[0]?.RoutineID || null;

    await conn.query(
      'INSERT INTO Audit_Log (UserID, QueryText, Severity, ActionTaken, RoutineID) VALUES (?, ?, ?, ?, ?)',
      [userId, 'MANUAL LOCK', 'HIGH', 'Account locked by admin', routineId]
    );

    await conn.commit();

    res.json({ ok: true });

  } catch (e) {
    await conn.rollback();
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});


app.post('/unlock-user', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const { userId } = req.body;

    if (!userId)
      return res.status(400).json({ ok: false, error: 'Missing userId' });

    await conn.beginTransaction();

    // First, delete suspicious_activity records linked to this user's audit logs
    await conn.query(
      `DELETE sa FROM suspicious_activity sa
       INNER JOIN Audit_Log al ON sa.LogID = al.LogID
       WHERE al.UserID = ?`,
      [userId]
    );

    // Then delete all audit logs for this user
    await conn.query(
      'DELETE FROM Audit_Log WHERE UserID = ?',
      [userId]
    );

    // Update user status to ACTIVE
    await conn.query(
      'UPDATE UserAccount SET Status = ? WHERE UserID = ?',
      ['ACTIVE', userId]
    );

    // Get MANUAL_UNLOCK routine
    const [unlockRoutine] = await conn.query(
      'SELECT RoutineID FROM Handler_Routine WHERE ThreatType = ? LIMIT 1',
      ['MANUAL_UNLOCK']
    );
    const routineId = unlockRoutine[0]?.RoutineID || null;

    // Add new unlock log entry
    await conn.query(
      'INSERT INTO Audit_Log (UserID, QueryText, Severity, ActionTaken, RoutineID) VALUES (?, ?, ?, ?, ?)',
      [userId, 'MANUAL UNLOCK — risk reset', 'LOW', 'Account unlocked by admin', routineId]
    );

    await conn.commit();
    res.json({ ok: true });

  } catch (e) {
    await conn.rollback();
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});


app.post('/lock-high-risk', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const [rows] = await conn.query(
      `SELECT u.UserID, u.RoleID,
              SUM(CASE WHEN al.Severity='HIGH' THEN 1 ELSE 0 END) AS HighCnt
       FROM UserAccount u
       LEFT JOIN Audit_Log al ON u.UserID = al.UserID
       WHERE u.Status = 'ACTIVE'
       GROUP BY u.UserID`
    );

    const filtered = rows.filter(u =>
      u.RoleID !== 1 &&
      (u.HighCnt * 15) >= AUTO_LOCK_RISK_THRESHOLD
    );

    await conn.beginTransaction();

    // Get AUTO_LOCK routine
    const [autoLockRoutine] = await conn.query(
      'SELECT RoutineID FROM Handler_Routine WHERE ThreatType = ? LIMIT 1',
      ['AUTO_LOCK']
    );
    const routineId = autoLockRoutine[0]?.RoutineID || null;

    const lockedIds = [];

    for (const u of filtered) {
      await conn.query(
        'UPDATE UserAccount SET Status = ? WHERE UserID = ?',
        ['LOCKED', u.UserID]
      );

      await conn.query(
        'INSERT INTO Audit_Log (UserID, QueryText, Severity, ActionTaken, RoutineID) VALUES (?, ?, ?, ?, ?)',
        [u.UserID, `Batch lock - high risk (${u.HighCnt} violations)`, 'HIGH', 'Account auto-locked', routineId]
      );

      lockedIds.push(u.UserID);
    }

    await conn.commit();

    res.json({ ok: true, locked: lockedIds });

  } catch (e) {
    await conn.rollback();
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});

// ---------------------- NEW DCL ROUTES ---------------------- //

// Get all database users and their privileges
app.get('/database-users', async (req, res) => {
  try {
    const [users] = await pool.query(
      `SELECT DISTINCT user, host 
       FROM mysql.user 
       WHERE user IN ('admin_user', 'security_user', 'auditor_user', 'developer_user', 'guest_user')
       ORDER BY user`
    );

    res.json({ ok: true, users });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Get privileges for a specific database user
app.get('/user-privileges/:username', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const { username } = req.params;
    
    // Get privileges using SHOW GRANTS
    const [grants] = await conn.query(`SHOW GRANTS FOR '${username}'@'localhost'`);
    
    // Parse grants into structured format
    const privileges = grants.map(g => {
      const grantText = Object.values(g)[0];
      return { grant: grantText };
    });

    res.json({ ok: true, username, privileges });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});

// Get comprehensive privilege summary for all DCL users
app.get('/privilege-summary', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const dclUsers = ['admin_user', 'security_user', 'auditor_user', 'developer_user', 'guest_user'];
    const summary = [];

    for (const user of dclUsers) {
      try {
        const [grants] = await conn.query(`SHOW GRANTS FOR '${user}'@'localhost'`);
        
        const privileges = grants.map(g => Object.values(g)[0]);
        
        // Parse privileges to extract key info
        const privilegeTypes = [];
        const tables = [];
        
        privileges.forEach(priv => {
          if (priv.includes('ALL PRIVILEGES')) {
            privilegeTypes.push('ALL PRIVILEGES');
          } else if (priv.includes('SELECT')) {
            privilegeTypes.push('SELECT');
          }
          if (priv.includes('INSERT')) privilegeTypes.push('INSERT');
          if (priv.includes('UPDATE')) privilegeTypes.push('UPDATE');
          if (priv.includes('DELETE')) privilegeTypes.push('DELETE');
          
          // Extract table names
          const tableMatch = priv.match(/ON `.*?`\.`(.*?)`/);
          if (tableMatch) {
            tables.push(tableMatch[1]);
          } else if (priv.includes('ON `DataJeopardyDB`.*')) {
            tables.push('ALL TABLES');
          }
        });

        summary.push({
          user,
          host: 'localhost',
          privileges: [...new Set(privilegeTypes)],
          tables: [...new Set(tables)],
          rawGrants: privileges
        });
        
      } catch (err) {
        summary.push({
          user,
          host: 'localhost',
          error: 'User not found or insufficient permissions'
        });
      }
    }

    res.json({ ok: true, summary });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});

// Grant privilege to a database user
app.post('/grant-privilege', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const { username, privilege, tableName } = req.body;
    
    if (!username || !privilege)
      return res.status(400).json({ ok: false, error: 'Missing required fields' });

    const table = tableName || '*';
    const grantQuery = `GRANT ${privilege} ON \`${DB_NAME}\`.\`${table}\` TO '${username}'@'localhost'`;
    
    await conn.query(grantQuery);
    await conn.query('FLUSH PRIVILEGES');

    res.json({ ok: true, message: `Granted ${privilege} to ${username}` });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});

// Revoke privilege from a database user
app.post('/revoke-privilege', async (req, res) => {
  const conn = await pool.getConnection();
  
  try {
    const { username, privilege, tableName } = req.body;
    
    if (!username || !privilege)
      return res.status(400).json({ ok: false, error: 'Missing required fields' });

    const table = tableName || '*';
    const revokeQuery = `REVOKE ${privilege} ON \`${DB_NAME}\`.\`${table}\` FROM '${username}'@'localhost'`;
    
    await conn.query(revokeQuery);
    await conn.query('FLUSH PRIVILEGES');

    res.json({ ok: true, message: `Revoked ${privilege} from ${username}` });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  } finally {
    conn.release();
  }
});

// Get database user activity mapping
app.get('/dcl-user-mapping', async (req, res) => {
  try {
    // Map DCL users to application roles
    const mapping = [
      {
        dclUser: 'admin_user',
        appRole: 'Admin',
        description: 'Full database access - all operations',
        privilegeLevel: 'FULL'
      },
      {
        dclUser: 'security_user',
        appRole: 'Security',
        description: 'Read access to Audit_Log and Suspicious_Activity',
        privilegeLevel: 'READ_SECURITY'
      },
      {
        dclUser: 'auditor_user',
        appRole: 'Auditor',
        description: 'Read-only access to all tables',
        privilegeLevel: 'READ_ALL'
      },
      {
        dclUser: 'developer_user',
        appRole: 'Developer',
        description: 'Read/Write Handler_Routine, Read UserAccount',
        privilegeLevel: 'LIMITED_WRITE'
      },
      {
        dclUser: 'guest_user',
        appRole: 'Guest',
        description: 'Read-only access to Role table',
        privilegeLevel: 'MINIMAL'
      }
    ];

    res.json({ ok: true, mapping });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


const HOST = process.env.API_HOST || '0.0.0.0';

app.listen(API_PORT, HOST, () => {
  console.log(`Server running: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${API_PORT}`);
});
