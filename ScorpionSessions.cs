﻿using System;
using System.Linq;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Threading;

namespace ScorpionHttpSessions
{
    public class ScorpionHttpSessions
    {
        public ScorpionHttpSessions(string host, int port)
        {
            schso = new ScorpionHttpSessionsObjects(host, port);
        }

        private ScorpionHttpSessionsObjects schso;

        public string newSession(string path, string IPv4, int PORT)
        {
            return Convert.ToString(schso.newSession(path, IPv4, PORT));
        }

        public bool verifySession(string token, string IPv4, int PORT)
        {
            return schso.verifySession(token, IPv4, PORT);
        }
    }

    /*
    * This class contains all objects related to a session such as tokens and session variables for all users
    */
    class ScorpionHttpSessionsObjects
    {
        //Session related objects
        internal struct session_data
        {
            public session_data(string token_, string accessible_path, string IPv4, int PORT)
            {
                token = token_;
                path = accessible_path;
                utc_time_created = DateTime.UtcNow.Ticks;
                utc_time_expire = DateTime.UtcNow.Ticks + 86400000;
                this.IPv4 = IPv4;
                this.PORT = PORT;
            }

            //Instead of every object running their own timer in order to dispose I created a big one outside, as its less costly
            readonly string token;
            readonly string path;
            public readonly string IPv4;
            public readonly int PORT;
            public readonly long utc_time_created;
            public readonly long utc_time_expire;
        };

        //Token related objects
        //Short tokens are 16 byte tokens sent to the user for AUTH, FULL_TOKEN's are used internally
        internal Dictionary<string, session_data> sessions;
        Timer t_cleanup;
        internal ScorpionNetworkDriver.ScorpionDriver scorpion_network_driver;

        public ScorpionHttpSessionsObjects(string host, int port)
        {
            scorpion_network_driver = new ScorpionNetworkDriver.ScorpionDriver(host, port);
            sessions = new Dictionary<string, session_data>();
            //1 day is 86400000 milliseconds, for test purposes we will run it at 10000
            t_cleanup = new Timer(cleanUp, null, 0, 86400000);
            return;
        }

        internal void cleanUp(Object status)
        {
            foreach(KeyValuePair<string, session_data> session in (IDictionary<string, session_data>)sessions)
            {
                //If time longer than a day or equal then kill
                if(DateTime.UtcNow.Ticks - ((session_data)session.Value).utc_time_created >= ((session_data)session.Value).utc_time_expire)
                    deleteSession(session.Key);
            }
            return;
        }

        internal void deleteSession(string session)
        {
            lock(sessions)
            {
                sessions.Remove(session);
                Console.WriteLine("Deleted session: {0}, remaining sessions are: {1}", session, sessions.Count);
            }
            return;
        }

        public string newSession(string path, string IPv4, int PORT)
        {
            int attempt = 0;
            string token = "\0";

            //Continue generating if user exists for 3 times
            while(attempt < 3)
            {
                token = generate16Rand();

                if(!checkTokenExists(token))
                {
                    //Add user and user data
                    sessions.Add(token, new session_data(token, path, IPv4, PORT));
                    break;
                }
            }
            Console.WriteLine("New session: {0}", token);
            return token;
        }

        public bool verifySession(string hash, string IPv4, int PORT)
        {
            //Check if hash exists as a key in struct:sessions, if not return false; if yes return true by default
            Console.WriteLine("Got session: {0}\nVerifying session..", hash);
            
            //If the sessions dictionary does not contain the token as a key
            if (!sessions.ContainsKey(hash))
                return false;
            
            //Else check the Clients originating IP is the same as that during creation
            else
            {
                if(sessions[hash].IPv4 != IPv4)// || sessions[hash].PORT != PORT)
                    return false;
            }
            //If the value is in the dictionary continue
            return true;
        }

        private bool checkTokenExists(string token)
        {
            return sessions.ContainsKey(token);
        }

        private string generate16Rand()
        {
            string returnable = "";
            Random r = new Random(((int)DateTime.Now.Ticks));

            for(int i = 0; i < 16; i++)
                returnable += r.Next(33, 126);

            return returnable;
        }
    }
}
