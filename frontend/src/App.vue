<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useAuth } from './stores/auth'

const auth = useAuth()
const router = useRouter()
async function logout() {
  await auth.logout()
  await router.push('/login')
}
</script>

<template>
  <header v-if="auth.me" class="bar">
    <nav>
      <RouterLink to="/">Inicio</RouterLink>
      <RouterLink v-if="auth.can('user:read')" to="/usuarios">Usuarios</RouterLink>
    </nav>
    <span>{{ auth.me.fullName }}</span>
    <button type="button" @click="logout">Salir</button>
  </header>
  <main><RouterView /></main>
</template>

<style>
body { font-family: system-ui, sans-serif; margin: 0; color: #1c1c1e; }
main { max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
.bar { display: flex; gap: 1rem; align-items: center; padding: .75rem 1rem; background: #f2f2f7; }
.bar nav { flex: 1; display: flex; gap: 1rem; }
label { display: block; margin: .75rem 0 .25rem; }
input { width: 100%; padding: .5rem; box-sizing: border-box; }
button { margin-top: 1rem; padding: .5rem 1rem; }
.error { color: #b00020; margin-top: .75rem; }
</style>
