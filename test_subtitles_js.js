const axios = require('axios');

async function checkSubtitlesJs() {
  const liveServer = 'https://server-nextjs-film.onrender.com';
  const subUrl = 'https://cloudorchestranova.com/embed/iframe_player/assets/subtitles.js?v=1786492668';

  try {
    const res = await axios.get(`${liveServer}/api/vidsrc/proxy?url=${encodeURIComponent(subUrl)}`, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      responseType: 'text'
    });

    const text = res.data;
    console.log('Contains patched imdb logic:', text.includes('var imdb = d.imdb_id || CONFIG.imdb'));
    console.log('Contains patched filter logic:', text.includes('endsWith(\'.ass\')'));

    const idx = text.indexOf('SUB.imdbId =');
    if (idx >= 0) console.log('Snippet around SUB.imdbId:', text.substring(idx-50, idx+200));
  } catch(e) {
    console.error('Error:', e.message);
  }
}

checkSubtitlesJs();
