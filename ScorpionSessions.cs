using System;
using System.Linq;
using System.Text;
using System.Security;
using System.Collections.Generic;

namespace ScorpionHttpSessions
{
    public class ScorpionHttpSessions
    {
        private ScorpionHttpSessionsObjects schso = new ScorpionHttpSessionsObjects();

        public string newSession(string path)
        {
            return Convert.ToString(schso.newSession(path));
        }

        public bool verifySession(string hash)
        {
            return schso.verifySession(Convert.ToInt32(hash));
        }
    }

    /*
    * This class contains all objects related to a session such as tokens and session variables for all users
    */
    class ScorpionHttpSessionsObjects
    {
        //Session related objects
        private readonly struct session_data
        {
            public session_data(SecureString token_private, int token_hash, string accessible_path)
            {
                private_token = token_private;
                hash = token_hash;
                path = accessible_path;
                private_token.MakeReadOnly();
                return;
            }

            public bool compareHash(int hash)
            {
                return hash == private_token.GetHashCode() ? true : false;
            }

            public void dispose()
            {
                private_token.Dispose();
            }

            readonly SecureString private_token;
            readonly int hash;
            readonly string path;
        };

        //Token related objects
        //Short tokens are 16 byte tokens sent to the user for AUTH, FULL_TOKEN's are used internally
        private Dictionary<int, session_data> sessions;

        public ScorpionHttpSessionsObjects()
        {
            sessions = new Dictionary<int, session_data>();
            return;
        }

        public int newSession(string path)
        {
            int attempt = 0, token_hash = 0;
            SecureString private_token;

            //Continue generating if user exists for 3 times
            while(attempt < 3)
            {
                private_token = generateToken();
                token_hash = private_token.GetHashCode();

                if(!checkHashExists(token_hash))
                {
                    //Add user and user data
                    sessions.Add(token_hash, new session_data(private_token, token_hash, path));
                    break;
                }
            }
            Console.WriteLine("New session: {0}", token_hash);
            return token_hash;
        }

        public bool verifySession(int hash)
        {
            session_data sd;

            //Check if hash exists as a key in struct:sessions, if not return false; if yes continue
            Console.WriteLine("Got session: {0}", hash);
            if (!sessions.TryGetValue(hash, out sd)) {
                return false;
            }

            //If the value is in the dictionary continue
            return sd.compareHash(hash);
        }

        private bool checkHashExists(int token)
        {
            return sessions.ContainsKey(token);
        }

        public SecureString generateToken()
        {
            //Get private token
            return generate256RandSafe();
        }

        private SecureString generate256RandSafe()
        {
            SecureString returnable = new SecureString();
            Random r = new Random(((int)DateTime.Now.Ticks));

            for(int i = 0; i < 256; i++)
                returnable.AppendChar((char)r.Next(33, 126));

            return returnable;
        }
    }
}
