--
-- PostgreSQL database dump
--

\restrict a55DUg588Jb2SQW4MigCHiFi4gYjP0A7BGFhPZJcrWpYwmRTIDYzar0phwYtwNz

-- Dumped from database version 15.15
-- Dumped by pg_dump version 15.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: Audios; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public."Audios" (
    id integer NOT NULL,
    filename character varying(255) NOT NULL,
    path character varying(255) NOT NULL,
    url character varying(255) NOT NULL,
    "uploadDate" timestamp with time zone,
    "userId" integer NOT NULL,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


ALTER TABLE public."Audios" OWNER TO postgres;

--
-- Name: Audios_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public."Audios_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."Audios_id_seq" OWNER TO postgres;

--
-- Name: Audios_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public."Audios_id_seq" OWNED BY public."Audios".id;


--
-- Name: audios; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.audios (
    id integer NOT NULL,
    filename character varying(255) NOT NULL,
    path character varying(255) NOT NULL,
    url character varying(255) NOT NULL,
    "uploadDate" timestamp with time zone,
    "userId" integer NOT NULL,
    reactions jsonb DEFAULT '{}'::jsonb,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


ALTER TABLE public.audios OWNER TO postgres;

--
-- Name: audios_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.audios_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.audios_id_seq OWNER TO postgres;

--
-- Name: audios_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.audios_id_seq OWNED BY public.audios.id;


--
-- Name: bookmarks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.bookmarks (
    id integer NOT NULL,
    user_id integer NOT NULL,
    audio_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.bookmarks OWNER TO postgres;

--
-- Name: bookmarks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.bookmarks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.bookmarks_id_seq OWNER TO postgres;

--
-- Name: bookmarks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.bookmarks_id_seq OWNED BY public.bookmarks.id;


--
-- Name: eavedrops; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.eavedrops (
    id integer NOT NULL,
    audience_id integer NOT NULL,
    target_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.eavedrops OWNER TO postgres;

--
-- Name: eavedrops_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.eavedrops_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.eavedrops_id_seq OWNER TO postgres;

--
-- Name: eavedrops_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.eavedrops_id_seq OWNED BY public.eavedrops.id;


--
-- Name: login_audit; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.login_audit (
    id integer NOT NULL,
    user_id integer NOT NULL,
    ip_address text,
    user_agent text,
    "timestamp" timestamp with time zone DEFAULT now()
);


ALTER TABLE public.login_audit OWNER TO postgres;

--
-- Name: login_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.login_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.login_audit_id_seq OWNER TO postgres;

--
-- Name: login_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.login_audit_id_seq OWNED BY public.login_audit.id;


--
-- Name: secrets; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.secrets (
    id integer NOT NULL,
    user_id integer NOT NULL,
    secret text NOT NULL,
    reactions jsonb DEFAULT '{}'::jsonb,
    reported boolean DEFAULT false,
    "timestamp" timestamp with time zone DEFAULT now(),
    type character varying,
    category character varying(50)
);


ALTER TABLE public.secrets OWNER TO postgres;

--
-- Name: secrets_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.secrets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.secrets_id_seq OWNER TO postgres;

--
-- Name: secrets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.secrets_id_seq OWNED BY public.secrets.id;


--
-- Name: session; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.session (
    sid character varying NOT NULL,
    sess json NOT NULL,
    expire timestamp(6) without time zone NOT NULL
);


ALTER TABLE public.session OWNER TO postgres;

--
-- Name: text_bookmarks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.text_bookmarks (
    id integer NOT NULL,
    user_id integer NOT NULL,
    secret_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.text_bookmarks OWNER TO postgres;

--
-- Name: text_bookmarks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.text_bookmarks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.text_bookmarks_id_seq OWNER TO postgres;

--
-- Name: text_bookmarks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.text_bookmarks_id_seq OWNED BY public.text_bookmarks.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    email character varying(255) NOT NULL,
    password text NOT NULL,
    profile_picture text,
    active_status boolean DEFAULT false,
    verified boolean DEFAULT false,
    display_user boolean DEFAULT false,
    login_code character varying(6),
    login_code_expires timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    color character varying(50),
    stealth_mode boolean DEFAULT false,
    avatar_alt character varying
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: Audios id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Audios" ALTER COLUMN id SET DEFAULT nextval('public."Audios_id_seq"'::regclass);


--
-- Name: audios id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.audios ALTER COLUMN id SET DEFAULT nextval('public.audios_id_seq'::regclass);


--
-- Name: bookmarks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.bookmarks ALTER COLUMN id SET DEFAULT nextval('public.bookmarks_id_seq'::regclass);


--
-- Name: eavedrops id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.eavedrops ALTER COLUMN id SET DEFAULT nextval('public.eavedrops_id_seq'::regclass);


--
-- Name: login_audit id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login_audit ALTER COLUMN id SET DEFAULT nextval('public.login_audit_id_seq'::regclass);


--
-- Name: secrets id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.secrets ALTER COLUMN id SET DEFAULT nextval('public.secrets_id_seq'::regclass);


--
-- Name: text_bookmarks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.text_bookmarks ALTER COLUMN id SET DEFAULT nextval('public.text_bookmarks_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: Audios; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public."Audios" (id, filename, path, url, "uploadDate", "userId", "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: audios; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.audios (id, filename, path, url, "uploadDate", "userId", reactions, "createdAt", "updatedAt") FROM stdin;
\.


--
-- Data for Name: bookmarks; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.bookmarks (id, user_id, audio_id, created_at) FROM stdin;
\.


--
-- Data for Name: eavedrops; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.eavedrops (id, audience_id, target_id, created_at) FROM stdin;
\.


--
-- Data for Name: login_audit; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.login_audit (id, user_id, ip_address, user_agent, "timestamp") FROM stdin;
1	1	127.0.0.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36	2026-02-03 08:27:56.251176-08
2	1	127.0.0.1	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36	2026-02-03 08:35:08.6549-08
3	1	127.0.0.1	Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36	2026-02-03 08:36:39.463076-08
4	1	127.0.0.1	Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36	2026-02-03 08:37:17.275273-08
5	1	127.0.0.1	Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36	2026-02-03 08:43:07.216429-08
6	1	127.0.0.1	Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36	2026-02-03 08:44:49.862181-08
\.


--
-- Data for Name: secrets; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.secrets (id, user_id, secret, reactions, reported, "timestamp", type, category) FROM stdin;
2	1	Hello	{"like": {"count": 1, "timestamp": "2026-02-04T05:20:54Z"}}	f	2026-02-04 04:50:04.994122-08	text	\N
3	2	hello	{}	f	2026-02-04 05:44:02.444556-08	text	\N
\.


--
-- Data for Name: session; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.session (sid, sess, expire) FROM stdin;
5w27wtRR2ULZ4d8G5hC0tTtuVamI5vtb	{"cookie":{"originalMaxAge":86400000,"expires":"2026-02-05T13:45:10.335Z","secure":false,"httpOnly":true,"path":"/","sameSite":"lax"},"passport":{"user":1},"isVerified":true}	2026-02-05 05:53:27
\.


--
-- Data for Name: text_bookmarks; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.text_bookmarks (id, user_id, secret_id, created_at) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (id, username, email, password, profile_picture, active_status, verified, display_user, login_code, login_code_expires, created_at, color, stealth_mode, avatar_alt) FROM stdin;
2	red	red@gmail.com	$2a$10$a2C.Nr7FlP94.O8Cx6DmNuZkuen0D6iWJVHfZf6125srTpLHrqc.K	/img/avatars/thumbs/phantom.jpg	f	f	f	\N	\N	2026-02-04 05:00:24.431037-08	\N	f	phantom
1	dab	dab@gmail.com	$2a$10$fuu4o7x4XnHuQGswe0.I5u2iTCxjWxTl3K8FbC/VSztWsMqoFSaFq	\N	f	f	f	938147	2026-02-04 05:55:09.13-08	2026-02-03 08:27:13.553049-08	\N	f	\N
\.


--
-- Name: Audios_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public."Audios_id_seq"', 1, false);


--
-- Name: audios_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.audios_id_seq', 1, false);


--
-- Name: bookmarks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.bookmarks_id_seq', 1, false);


--
-- Name: eavedrops_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.eavedrops_id_seq', 1, false);


--
-- Name: login_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.login_audit_id_seq', 6, true);


--
-- Name: secrets_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.secrets_id_seq', 3, true);


--
-- Name: text_bookmarks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.text_bookmarks_id_seq', 1, false);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_id_seq', 2, true);


--
-- Name: Audios Audios_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."Audios"
    ADD CONSTRAINT "Audios_pkey" PRIMARY KEY (id);


--
-- Name: audios audios_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.audios
    ADD CONSTRAINT audios_pkey PRIMARY KEY (id);


--
-- Name: bookmarks bookmarks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.bookmarks
    ADD CONSTRAINT bookmarks_pkey PRIMARY KEY (id);


--
-- Name: eavedrops eavedrops_audience_id_target_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.eavedrops
    ADD CONSTRAINT eavedrops_audience_id_target_id_key UNIQUE (audience_id, target_id);


--
-- Name: eavedrops eavedrops_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.eavedrops
    ADD CONSTRAINT eavedrops_pkey PRIMARY KEY (id);


--
-- Name: login_audit login_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login_audit
    ADD CONSTRAINT login_audit_pkey PRIMARY KEY (id);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: session session_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_pkey PRIMARY KEY (sid);


--
-- Name: text_bookmarks text_bookmarks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.text_bookmarks
    ADD CONSTRAINT text_bookmarks_pkey PRIMARY KEY (id);


--
-- Name: text_bookmarks text_bookmarks_user_id_secret_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.text_bookmarks
    ADD CONSTRAINT text_bookmarks_user_id_secret_id_key UNIQUE (user_id, secret_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: IDX_session_expire; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX "IDX_session_expire" ON public.session USING btree (expire);


--
-- Name: bookmarks bookmarks_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.bookmarks
    ADD CONSTRAINT bookmarks_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: eavedrops eavedrops_audience_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.eavedrops
    ADD CONSTRAINT eavedrops_audience_id_fkey FOREIGN KEY (audience_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: eavedrops eavedrops_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.eavedrops
    ADD CONSTRAINT eavedrops_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: login_audit login_audit_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.login_audit
    ADD CONSTRAINT login_audit_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: secrets secrets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: text_bookmarks text_bookmarks_secret_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.text_bookmarks
    ADD CONSTRAINT text_bookmarks_secret_id_fkey FOREIGN KEY (secret_id) REFERENCES public.secrets(id) ON DELETE CASCADE;


--
-- Name: text_bookmarks text_bookmarks_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.text_bookmarks
    ADD CONSTRAINT text_bookmarks_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict a55DUg588Jb2SQW4MigCHiFi4gYjP0A7BGFhPZJcrWpYwmRTIDYzar0phwYtwNz

